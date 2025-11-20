package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	msgtypes "trafRep/internal/stream/message_types"
)

// PostgreSQLMessage представляет одно логическое сообщение PostgreSQL от клиента к серверу,
// объединённое из одного или нескольких TCP-сегментов.
type PostgreSQLMessage struct {
	FirstTCPPacketTimestamp  time.Time
	LastTCPPacketTimestamp   time.Time
	CommandCompleteTimestamp time.Time
	ReadyForQueryTimestamp   time.Time
	Type                     msgtypes.ClientMessageType
	Len                      uint32
	Payload                  []byte
}

// PrettyQuery возвращает строку с SQL запросом для вывода.
func (m PostgreSQLMessage) PrettyQuery() string {
	return strings.TrimSpace(string(m.Payload[:len(m.Payload)-1]))
}

// Row возвращает байтовое представление сообщения в том виде, которое нужно отправлять.
func (m PostgreSQLMessage) Row() []byte {
	if m.Type.HaveTypeByte() {
		return m.typedByteRow()
	}
	return m.untypedByteRow()
}

func (m PostgreSQLMessage) typedByteRow() []byte {
	buf := make([]byte, m.Len+1)
	buf[0] = byte(m.Type)
	binary.BigEndian.PutUint32(buf[1:5], m.Len)
	copy(buf[5:], m.Payload)
	return buf
}

func (m PostgreSQLMessage) untypedByteRow() []byte {
	buf := make([]byte, m.Len)
	binary.BigEndian.PutUint32(buf[0:4], m.Len)
	copy(buf[4:], m.Payload)
	return buf
}

// TCPStream хранит буферы и сегменты для двух направлений одного TCP-потока.
type TCPStream struct {
	clientBuf                []byte
	clientSegs               segments
	serverBuf                []byte
	serverSegs               segments
	completed                []PostgreSQLMessage
	needCommandCompleteIndex int
	needReadyForQueryIndex   int
}

// NewTCPStream создаёт и возвращает новый экземпляр TCPStream.
func NewTCPStream() *TCPStream {
	return &TCPStream{
		clientBuf:  make([]byte, 0),
		clientSegs: make([]segment, 0),
		serverBuf:  make([]byte, 0),
		serverSegs: make([]segment, 0),
		completed:  make([]PostgreSQLMessage, 0),
	}
}

// Reset очищает все внутренние буферы и сегменты TCPStream.
func (s *TCPStream) Reset() {
	s.clientBuf = s.clientBuf[:0]
	s.clientSegs = s.clientSegs[:0]
	s.serverBuf = s.serverBuf[:0]
	s.serverSegs = s.serverSegs[:0]
	s.completed = s.completed[:0]
}

// segment представляет один TCP пакет с его длиной и временной меткой.
type segment struct {
	length uint32
	ts     time.Time
}

type segments []segment

func (s segments) timestampByOffset(offset int) time.Time {
	var acc uint32 = 0
	for _, seg := range s {
		if uint32(offset) < acc+seg.length {
			return seg.ts
		}
		acc += seg.length
	}
	return time.Time{}
}

// TCPStreamManager управляет множеством TCPStream и обеспечивает
// сборку полных PostgreSQL‑сообщений и связывание CommandComplete.
type TCPStreamManager struct {
	streams map[string]*TCPStream
}

// NewTCPStreamManager создаёт и возвращает новый менеджер TCP-потоков.
func NewTCPStreamManager() *TCPStreamManager {
	return &TCPStreamManager{
		streams: make(map[string]*TCPStream),
	}
}

// AddPacket добавляет один TCP-пакет в поток с идентификатором key.
// serverPort используется для определения направления (client<->server).
// Данные от клиента накапливаются и из них извлекаются полные PostgreSQL‑сообщения,
// которые сохраняются во внутреннем срезе completed.
// Данные от сервера накапливаются и сканируются на предмет сообщений типа CommandComplete и ReadyForQuery.
// Для найденного типа выставляется Timestamp для первой незавершённой клиентской записи в completed.
func (m *TCPStreamManager) AddPacket(data []byte, timestamp time.Time, ipSrc, ipDst string, portSrc, portDst uint16, serverIp string, serverPort uint16) error {
	isFromServer := ipSrc == serverIp && portSrc == serverPort

	key := fmt.Sprintf("%s:%d->%s:%d", ipSrc, portSrc, ipDst, portDst)
	if isFromServer {
		key = fmt.Sprintf("%s:%d->%s:%d", ipDst, portDst, ipSrc, portSrc)
	}

	stream, ok := m.streams[key]
	if !ok {
		stream = NewTCPStream()
		m.streams[key] = stream
	}

	if data == nil {
		return errors.New("data is nil")
	}
	if len(data) < 4 {
		return errors.New("data length less than 4 bytes")
	}

	if isFromServer {
		stream.addServerData(data, timestamp)
	} else {
		stream.addClientData(data, timestamp)
	}

	return nil
}

// CollectMessages возвращает все собранные клиентские сообщения из текущих потоков.
// После возврата сообщения и все внутренние буферы/сегменты потока очищаются,
// а поток удаляется из менеджера (освобождение памяти и сброс состояния).
func (m *TCPStreamManager) CollectMessages() []PostgreSQLMessage {
	var out []PostgreSQLMessage
	for key, s := range m.streams {
		if len(s.completed) > 0 {
			out = append(out, s.completed...)
		}
		s.Reset()
		delete(m.streams, key)
	}
	return out
}

func (s *TCPStream) addClientData(data []byte, timestamp time.Time) {
	s.clientBuf = append(s.clientBuf, data...)
	s.clientSegs = append(s.clientSegs, segment{length: uint32(len(data)), ts: timestamp})
	s.parseClientBuffer()
}

func (s *TCPStream) addServerData(data []byte, timestamp time.Time) {
	s.serverBuf = append(s.serverBuf, data...)
	s.serverSegs = append(s.serverSegs, segment{length: uint32(len(data)), ts: timestamp})
	s.parseServerBuffer()
}

// tryCreateTypedMessage пытается создать PostgreSQLMessage с типом.
func (s *TCPStream) tryCreateTypedMessage() (msg PostgreSQLMessage, processed int) {
	msgType := s.clientMessageType()
	dataLen := int(binary.BigEndian.Uint32(s.clientBuf[1:5]))
	total := 1 + dataLen
	if len(s.clientBuf) < total {
		return PostgreSQLMessage{}, 0
	}
	payloadLen := dataLen - 4
	payload := make([]byte, payloadLen)
	copy(payload, s.clientBuf[5:5+payloadLen])
	msgFirstTs := s.clientSegs.timestampByOffset(0)
	msgLastTs := s.clientSegs.timestampByOffset(total - 1)
	return PostgreSQLMessage{
			FirstTCPPacketTimestamp:  msgFirstTs,
			LastTCPPacketTimestamp:   msgLastTs,
			CommandCompleteTimestamp: time.Time{},
			Len:                      uint32(dataLen),
			Payload:                  payload,
			Type:                     msgType,
		},
		total
}

// tryCreateUntypedMessage пытается создать PostgreSQLMessage без типа.
func (s *TCPStream) tryCreateUntypedMessage() (msg PostgreSQLMessage, processed int) {
	remaining := s.clientBuf[:]
	dataLen := int(binary.BigEndian.Uint32(remaining[0:4]))
	if len(s.clientBuf) < dataLen {
		return PostgreSQLMessage{}, 0
	}
	payloadLen := dataLen - 4
	payload := make([]byte, payloadLen)
	copy(payload, remaining[4:4+payloadLen])
	msgFirstTs := s.clientSegs.timestampByOffset(0)
	msgLastTs := s.clientSegs.timestampByOffset(dataLen - 1)
	return PostgreSQLMessage{
		FirstTCPPacketTimestamp:  msgFirstTs,
		LastTCPPacketTimestamp:   msgLastTs,
		CommandCompleteTimestamp: time.Time{},
		Len:                      uint32(dataLen),
		Payload:                  payload,
		Type:                     msgtypes.ClientMessageTypeOnlyLength,
	}, dataLen

}

// parseClientBuffer извлекает целые PostgreSQLMessage из clientBuf и добавляет их в completed.
func (s *TCPStream) parseClientBuffer() {
	for len(s.clientBuf) > 3 {
		var msg PostgreSQLMessage
		var processed int

		msgType := s.clientMessageType()
		if msgType.HaveTypeByte() {
			msg, processed = s.tryCreateTypedMessage()
		} else {
			msg, processed = s.tryCreateUntypedMessage()
		}

		if processed > 0 {
			if !msg.Type.NeedCommandCompleteAnswer() {
				s.needCommandCompleteIndex++
			}
			if !msg.Type.NeedReadyForQueryAnswer() {
				s.needReadyForQueryIndex++
			}
			s.completed = append(s.completed, msg)
			s.clearProcessedBytes(processed)
		} else {
			break
		}
	}
}

func (s *TCPStream) clearProcessedBytes(processed int) {
	s.clientBuf = s.clientBuf[processed:]
	bytes := uint32(0)
	checkedSegs := 0
	for bytes < uint32(processed) {
		bytes += s.clientSegs[checkedSegs].length
		checkedSegs++
	}
	s.clientSegs = s.clientSegs[checkedSegs:]
}

// parseServerBuffer извлекает серверные сообщения из serverBuf и для каждого
// сообщения типа 'C' (CommandComplete) назначает CommandCompleteTimestamp для первой
// незавершённой клиентской записи в s.completed.
func (s *TCPStream) parseServerBuffer() { // TODO: сделать нормально
	var processed uint32 = 0

	for rem := uint32(len(s.serverBuf)) - processed; rem > 0; rem = uint32(len(s.serverBuf)) - processed {
		if rem < 5 {
			break
		}
		remaining := s.serverBuf[processed:]
		first := remaining[0]
		isASCIIType := (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z')
		if isASCIIType {
			lenField := binary.BigEndian.Uint32(remaining[1:5])
			if lenField <= 0 {
				break
			}
			total := uint32(1) + lenField
			if rem < total {
				break
			}

			if first == 'C' {
				ts := s.serverSegs.timestampByOffset(int(processed))
				s.assignCommandComplete(ts)
			}
			processed += total
			continue
		}

		lenField := binary.BigEndian.Uint32(remaining[0:4])
		if lenField <= 0 {
			break
		}
		total := lenField
		if rem < total {
			break
		}
		processed += total
	}

	if processed > 0 {
		if processed >= uint32(len(s.serverBuf)) {
			s.serverBuf = s.serverBuf[:0]
			s.serverSegs = s.serverSegs[:0]
		} else {
			s.serverBuf = s.serverBuf[processed:]
			rem := processed
			newSegs := make([]segment, 0, len(s.serverSegs))
			for _, seg := range s.serverSegs {
				if rem <= 0 {
					newSegs = append(newSegs, seg)
					continue
				}
				if rem < seg.length {
					seg.length -= rem
					newSegs = append(newSegs, seg)
					rem = 0
				} else {
					rem -= seg.length
				}
			}
			s.serverSegs = newSegs
		}
	}
}

func (s *TCPStream) assignCommandComplete(ts time.Time) {
	s.completed[s.needCommandCompleteIndex].CommandCompleteTimestamp = ts
	s.needCommandCompleteIndex++
}

func (s *TCPStream) assignReadyForQuery(ts time.Time) {
	s.completed[s.needReadyForQueryIndex].ReadyForQueryTimestamp = ts
	s.needReadyForQueryIndex++
}

func (s *TCPStream) clientMessageType() msgtypes.ClientMessageType {
	return msgtypes.ClientMessageType(s.clientBuf[0])
}

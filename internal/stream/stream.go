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
	if m.Type.IsNormalType() {
		return m.typedByteRow()
	}
	return m.untypedByteRow()
}

// typedByteRow возвращает байтовое представление сообщения, включая байт типа в начале.
// Формат: [type(1 byte)][len(4 bytes)][payload].
func (m PostgreSQLMessage) typedByteRow() []byte {
	buf := make([]byte, m.Len+1)
	buf[0] = byte(m.Type)
	binary.BigEndian.PutUint32(buf[1:5], m.Len)
	copy(buf[5:], m.Payload)
	return buf
}

// untypedByteRow возвращает байтовое представление сообщения без байта типа.
// Формат: [len(4 bytes)][payload].
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
	serverProcessedMessages  int
	completed                []PostgreSQLMessage
	needCommandCompleteIndex int
	needReadyForQueryIndex   int
	HaveAllMessages          bool
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
	activeStreams    map[string]*TCPStream
	completedStreams []*TCPStream
}

// NewTCPStreamManager создаёт и возвращает новый менеджер TCP-потоков.
func NewTCPStreamManager() *TCPStreamManager {
	return &TCPStreamManager{
		activeStreams: make(map[string]*TCPStream),
	}
}

// GetStreamMessages возвращает срез из срезов всех завершённых сообщений.
func (m *TCPStreamManager) GetStreamMessages() [][]PostgreSQLMessage {
	var allMessages [][]PostgreSQLMessage
	for _, stream := range m.completedStreams {
		allMessages = append(allMessages, stream.completed)
	}
	for _, stream := range m.activeStreams {
		allMessages = append(allMessages, stream.completed)
	}
	return allMessages
}

// AddPacket добавляет один TCP-пакет в поток с идентификатором key.
// Данные от клиента накапливаются и из них извлекаются полные PostgreSQL‑сообщения, которые сохраняются во внутреннем
// срезе completed.
// Данные от сервера накапливаются и сканируются на предмет сообщений типа CommandComplete и ReadyForQuery.
func (m *TCPStreamManager) AddPacket(data []byte, timestamp time.Time, ipSrc, ipDst string, portSrc, portDst uint16, serverIp string, serverPort uint16) error {
	isFromServer := ipSrc == serverIp && portSrc == serverPort

	key := m.createKey(isFromServer, ipSrc, ipDst, portSrc, portDst)

	stream, ok := m.activeStreams[key]
	if !ok {
		stream = NewTCPStream()
		m.activeStreams[key] = stream
	}
	if data == nil {
		return errors.New("data is nil")
	}
	if len(data) < 4 && !isFromServer {
		return errors.New("client cannot send less than 4 bytes")
	}
	if len(data) != 1 && msgtypes.IsSSLandGSSENCAnswer(data[0]) && len(data) < 5 && isFromServer {
		return errors.New(fmt.Sprintf("server cannot send %d byte(s)", len(data)))
	}

	if isFromServer {
		stream.addServerData(data, timestamp)
		stream.parseServerBuffer()
	} else {
		stream.addClientData(data, timestamp)
		stream.parseClientBuffer()
	}

	if stream.HaveAllMessages {
		m.completedStreams = append(m.completedStreams, stream)
		delete(m.activeStreams, key)
	}

	return nil
}

// createKey создаёт уникальный ключ для идентификации TCP-потока.
func (m *TCPStreamManager) createKey(isFromServer bool, ipSrc, ipDst string, portSrc, portDst uint16) string {
	key := fmt.Sprintf("%s:%d->%s:%d", ipSrc, portSrc, ipDst, portDst)
	if isFromServer {
		key = fmt.Sprintf("%s:%d->%s:%d", ipDst, portDst, ipSrc, portSrc)
	}
	return key
}

func (s *TCPStream) canBeStartupMessage() bool {
	return len(s.completed) == 0 ||
		s.completed[0].Type == msgtypes.SSLRequest ||
		s.completed[0].Type == msgtypes.GSSENCRequest
}

func (s *TCPStream) canBeCipherMessage() bool {
	return len(s.completed) == 0
}

// addClientData добавляет данные от клиента в буфер потока и регистрирует сегмент с меткой времени.
func (s *TCPStream) addClientData(data []byte, timestamp time.Time) {
	s.clientBuf = append(s.clientBuf, data...)
	s.clientSegs = append(s.clientSegs, segment{length: uint32(len(data)), ts: timestamp})
}

// addServerData добавляет данные от сервера в буфер потока и регистрирует сегмент с меткой времени.
func (s *TCPStream) addServerData(data []byte, timestamp time.Time) {
	s.serverBuf = append(s.serverBuf, data...)
	s.serverSegs = append(s.serverSegs, segment{length: uint32(len(data)), ts: timestamp})
}

// tryCreateClientTypedMessage пытается создать PostgreSQLMessage, когда присутствует байт типа.
// Возвращает сообщение и число обработанных байт (0 если недостаточно данных).
func (s *TCPStream) tryCreateClientTypedMessage() (msg PostgreSQLMessage, processed int) {
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
			Type:                     s.clientMessageType(),
		},
		total
}

// tryCreateClientUntypedMessage пытается создать PostgreSQLMessage для сообщений без типа (только длина).
// Возвращает сообщение и число обработанных байт (0 если недостаточно данных).
func (s *TCPStream) tryCreateClientUntypedMessage() (msg PostgreSQLMessage, processed int) {
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
		Type:                     s.clientMessageType(),
	}, dataLen

}

// clearClientProcessedBytes удаляет из clientBuf первые processed байт и соответствующие сегменты.
func (s *TCPStream) clearClientProcessedBytes(processed int) {
	s.clientBuf = s.clientBuf[processed:]
	bytes := uint32(0)
	checkedSegs := 0
	for checkedSegs < len(s.clientSegs) && bytes+s.clientSegs[checkedSegs].length < uint32(processed) {
		bytes += s.clientSegs[checkedSegs].length
		checkedSegs++
	}
	s.clientSegs = s.clientSegs[checkedSegs:]
}

// parseClientBuffer извлекает целые PostgreSQLMessage из clientBuf и добавляет их в completed.
func (s *TCPStream) parseClientBuffer() {
	for len(s.clientBuf) > 3 {
		var msg PostgreSQLMessage
		var processed int

		msgType := s.clientMessageType()
		if msgType.IsNormalType() {
			msg, processed = s.tryCreateClientTypedMessage()
		} else {
			msg, processed = s.tryCreateClientUntypedMessage()
		}
		if processed < 1 {
			break
		}
		if !msg.Type.NeedCommandCompleteAnswer() {
			s.needCommandCompleteIndex++
		}
		if !msg.Type.NeedReadyForQueryAnswer() {
			s.needReadyForQueryIndex++
		}
		s.completed = append(s.completed, msg)
		s.clearClientProcessedBytes(processed)
		if msgType == msgtypes.Terminate {
			s.HaveAllMessages = true
			break
		}
	}
}

// tryReadServerMessage пытается прочитать сообщение от сервера.
// Возвращает число обработанных байт (0 если недостаточно данных).
func (s *TCPStream) tryReadServerMessage() (processed int) {
	if s.canBeSSLandGSSENCAnswer() && msgtypes.IsSSLandGSSENCAnswer(s.serverBuf[0]) {
		return 1
	}
	dataLen := int(binary.BigEndian.Uint32(s.serverBuf[1:5]))
	total := 1 + dataLen
	if len(s.serverBuf) < total {
		return 0
	}
	return total
}

// clearServerProcessedBytes удаляет из serverBuf первые processed байт и соответствующие записи в serverSegs.
func (s *TCPStream) clearServerProcessedBytes(processed int) {
	s.serverBuf = s.serverBuf[processed:]
	bytes := uint32(0)
	checkedSegs := 0
	for checkedSegs < len(s.serverSegs) && bytes+s.serverSegs[checkedSegs].length < uint32(processed) {
		bytes += s.serverSegs[checkedSegs].length
		checkedSegs++
	}
	s.serverSegs = s.serverSegs[checkedSegs:]
}

func (s *TCPStream) canBeSSLandGSSENCAnswer() bool {
	return s.serverProcessedMessages == 0
}

// parseServerBuffer извлекает серверные сообщения из serverBuf и для каждого
// сообщения типа CommandComplete назначает CommandCompleteTimestamp для первой
// незавершённой клиентской записи в s.completed.
func (s *TCPStream) parseServerBuffer() {
	for len(s.serverBuf) > 4 || s.canBeSSLandGSSENCAnswer() {
		processed := s.tryReadServerMessage()
		if processed < 1 {
			break
		}
		s.serverProcessedMessages++
		msgLastTs := s.clientSegs.timestampByOffset(processed - 1)
		msgType := msgtypes.ServerMessageType(s.serverBuf[0])
		if msgType.IsCommandComplete() {
			s.assignCommandComplete(msgLastTs)
		} else if msgType.IsReadyForQuery() {
			s.assignReadyForQuery(msgLastTs)
		}

		s.clearServerProcessedBytes(processed)
	}
}

// assignCommandComplete устанавливает CommandCompleteTimestamp для следующего ожидающего сообщения.
func (s *TCPStream) assignCommandComplete(ts time.Time) {
	s.completed[s.needCommandCompleteIndex].CommandCompleteTimestamp = ts
	s.needCommandCompleteIndex++
}

// assignReadyForQuery устанавливает ReadyForQueryTimestamp для следующего ожидающего сообщения.
func (s *TCPStream) assignReadyForQuery(ts time.Time) {
	s.completed[s.needReadyForQueryIndex].ReadyForQueryTimestamp = ts
	s.needReadyForQueryIndex++
}

// clientMessageType возвращает тип клиентского сообщения.
func (s *TCPStream) clientMessageType() msgtypes.ClientMessageType {
	preliminaryType := msgtypes.ClientMessageType(s.clientBuf[0])
	msgLen := int(binary.BigEndian.Uint32(s.clientBuf[0:4]))
	if len(s.clientBuf) < msgLen {
		return preliminaryType
	}
	data := s.clientBuf[:msgLen]
	if s.canBeCipherMessage() {
		if msgtypes.IsSSLRequest(data) {
			return msgtypes.SSLRequest
		}
		if msgtypes.IsGSSENCRequest(data) {
			return msgtypes.GSSENCRequest
		}
	}
	if s.canBeStartupMessage() && !preliminaryType.IsNormalType() {
		return msgtypes.StartupMessage
	}
	return preliminaryType
}

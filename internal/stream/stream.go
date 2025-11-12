package stream

import (
	"encoding/binary"
	"strings"
	"time"

	"trafRep/internal/models"
)

// TCPStream хранит буферы и сегменты для двух направлений одного TCP-потока.
type TCPStream struct {
	clientBuf  []byte
	clientSegr []segment
	serverBuf  []byte
	serverSegr []segment
	completed  []models.PostgreSQLMessage
}

type segment struct {
	length uint32
	ts     time.Time
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
// Данные от сервера накапливаются и сканируются на предмет сообщений типа 'C' (CommandComplete).
// Для найденного CommandComplete выставляется CommandCompleteTimestamp для первой незавершённой
// клиентской записи в completed.
func (m *TCPStreamManager) AddPacket(key string, data []byte, timestamp time.Time, ipSrc, ipDst string, portSrc, portDst uint16, serverPort uint16) {
	stream, ok := m.streams[key]
	if !ok {
		stream = &TCPStream{
			clientBuf:  make([]byte, 0),
			clientSegr: make([]segment, 0),
			serverBuf:  make([]byte, 0),
			serverSegr: make([]segment, 0),
			completed:  make([]models.PostgreSQLMessage, 0),
		}
		m.streams[key] = stream
	}

	isFromServer := portSrc == serverPort

	if len(data) > 0 {
		if isFromServer {
			stream.serverBuf = append(stream.serverBuf, data...)
			stream.serverSegr = append(stream.serverSegr, segment{length: uint32(len(data)), ts: timestamp})
			stream.parseServerBuffer()
		} else {
			stream.clientBuf = append(stream.clientBuf, data...)
			stream.clientSegr = append(stream.clientSegr, segment{length: uint32(len(data)), ts: timestamp})
			stream.parseClientBuffer()
		}
	}
}

// CollectMessages возвращает все собранные клиентские сообщения из текущих потоков.
// После возврата сообщения и все внутренние буферы/сегменты потока очищаются,
// а поток удаляется из менеджера (освобождение памяти и сброс состояния).
func (m *TCPStreamManager) CollectMessages() []models.PostgreSQLMessage {
	var out []models.PostgreSQLMessage
	for key, s := range m.streams {
		if len(s.completed) > 0 {
			out = append(out, s.completed...)
		}
		s.completed = nil
		s.clientBuf = nil
		s.clientSegr = nil
		s.serverBuf = nil
		s.serverSegr = nil
		delete(m.streams, key)
	}
	return out
}

// parseClientBuffer извлекает целые клиентские PostgreSQL‑сообщения из clientBuf
// и добавляет их в s.completed. Поддерживаются два формата:
// 1) typed: 1 байт type + 4 байта length (big-endian) + payload
// 2) length-only: 4 байта length + payload (Startup/SSLRequest).
func (s *TCPStream) parseClientBuffer() {
	var processed uint32 = 0

	for rem := uint32(len(s.clientBuf)) - processed; rem > 4; rem = uint32(len(s.clientBuf)) - processed {
		remaining := s.clientBuf[processed:]
		first := remaining[0]
		isASCIIType := (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z')

		if isASCIIType {
			lenField := binary.BigEndian.Uint32(remaining[1:5])
			total := 1 + lenField
			if rem < total {
				break
			}
			payloadLen := lenField - 4
			payload := make([]byte, payloadLen)
			copy(payload, remaining[5:5+payloadLen])
			msgFirstTs := s.timestampForClientOffset(processed)
			msgLastTs := s.timestampForClientOffset(processed + total - 1)
			s.completed = append(s.completed, models.PostgreSQLMessage{
				FirstTCPPacketTimestamp:  msgFirstTs,
				LastTCPPacketTimestamp:   msgLastTs,
				CommandCompleteTimestamp: time.Time{},
				Len:                      uint32(lenField),
				Payload:                  payload,
				Type:                     models.ClientMessageType(first),
			})
			processed += total
			continue
		}

		lenField := binary.BigEndian.Uint32(remaining[0:4])
		if rem < lenField {
			break
		}
		payloadLen := lenField - 4
		payload := make([]byte, payloadLen)
		copy(payload, remaining[4:4+payloadLen])
		msgFirstTs := s.timestampForClientOffset(processed)
		msgLastTs := s.timestampForClientOffset(processed + lenField - 1)
		s.completed = append(s.completed, models.PostgreSQLMessage{
			FirstTCPPacketTimestamp:  msgFirstTs,
			LastTCPPacketTimestamp:   msgLastTs,
			CommandCompleteTimestamp: time.Time{},
			Len:                      lenField,
			Payload:                  payload,
			Type:                     0, // length-only
		})
		processed += lenField
	}

	if processed > 0 {
		if processed >= uint32(len(s.clientBuf)) {
			s.clientBuf = s.clientBuf[:0]
			s.clientSegr = s.clientSegr[:0]
		} else {
			s.clientBuf = s.clientBuf[processed:]
			rem := processed
			newSegs := make([]segment, 0, len(s.clientSegr))
			for _, seg := range s.clientSegr {
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
			s.clientSegr = newSegs
		}
	}
}

// parseServerBuffer извлекает серверные сообщения из serverBuf и для каждого
// сообщения типа 'C' (CommandComplete) назначает CommandCompleteTimestamp для первой
// незавершённой клиентской записи в s.completed.
func (s *TCPStream) parseServerBuffer() {
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
				ts := s.timestampForServerOffset(processed)
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
			s.serverSegr = s.serverSegr[:0]
		} else {
			s.serverBuf = s.serverBuf[processed:]
			rem := processed
			newSegs := make([]segment, 0, len(s.serverSegr))
			for _, seg := range s.serverSegr {
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
			s.serverSegr = newSegs
		}
	}
}

// assignCommandComplete выставляет CommandCompleteTimestamp для первой незавершённой
// записи в s.completed.
func (s *TCPStream) assignCommandComplete(ts time.Time) {
	for i := range s.completed {
		if s.completed[i].CommandCompleteTimestamp.IsZero() {
			s.completed[i].CommandCompleteTimestamp = ts
			return
		}
	}
}

// timestampForClientOffset возвращает время сегмента клиента, содержащего байт с указанным offset.
func (s *TCPStream) timestampForClientOffset(offset uint32) time.Time {
	if offset < 0 {
		return time.Time{}
	}
	var acc uint32 = 0
	for _, seg := range s.clientSegr {
		if offset < acc+seg.length {
			return seg.ts
		}
		acc += seg.length
	}
	return time.Time{}
}

// timestampForServerOffset возвращает время сегмента сервера, содержащего байт с указанным offset.
func (s *TCPStream) timestampForServerOffset(offset uint32) time.Time {
	if offset < 0 {
		return time.Time{}
	}
	var acc uint32 = 0
	for _, seg := range s.serverSegr {
		if offset < acc+seg.length {
			return seg.ts
		}
		acc += seg.length
	}
	return time.Time{}
}

// ExtractPrettyQuery возвращает строку с запросом.
func ExtractPrettyQuery(data []byte) string {
	return strings.TrimSpace(string(data[:len(data)-1]))
}

package stream

import (
	"encoding/binary"
	"time"

	"trafRep/internal/models"
)

// TCPStream хранит текущий буфер одного TCP-потока и список сегментов,
// где каждый сегмент соответствует одному исходному TCP-пакету с длиной и временем.
type TCPStream struct {
	buffer   []byte
	segments []segment
}

type segment struct {
	length int
	ts     time.Time
}

// TCPStreamManager управляет множеством TCPStream и обеспечивает
// сборка полных PostgreSQL-сообщений из последовательности TCP-пакетов.
type TCPStreamManager struct {
	streams map[string]*TCPStream
}

// NewTCPStreamManager создаёт менеджер потоков.
func NewTCPStreamManager() *TCPStreamManager {
	return &TCPStreamManager{
		streams: make(map[string]*TCPStream),
	}
}

// AddPacket добавляет данные TCP-пакета в поток, идентифицируемый key.
// Возвращает все полностью собранные PostgreSQL-сообщения, которые
// удалось извлечь после добавления этого пакета.
// Время каждого сообщения устанавливается в timestamp первого TCP-пакета,
// содержащего первый байт этого сообщения.
func (m *TCPStreamManager) AddPacket(key string, data []byte, timestamp time.Time, ipSrc, ipDst string, portSrc, portDst uint16) []models.PostgreSQLMessage {
	stream, ok := m.streams[key]
	if !ok {
		stream = &TCPStream{
			buffer:   make([]byte, 0),
			segments: make([]segment, 0),
		}
		m.streams[key] = stream
	}

	if len(data) > 0 {
		stream.buffer = append(stream.buffer, data...)
		stream.segments = append(stream.segments, segment{length: len(data), ts: timestamp})
	}

	messages := make([]models.PostgreSQLMessage, 0)
	processed := 0
	const maxMessageSize = 10 * 1024 * 1024 // 10 MB

	for {
		rem := len(stream.buffer) - processed
		if rem <= 0 {
			break
		}
		if rem < 4 {
			break
		}
		remaining := stream.buffer[processed:]

		first := remaining[0]
		isASCIIType := (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z')
		if isASCIIType && rem >= 5 {
			lenField := int(binary.BigEndian.Uint32(remaining[1:5]))
			if lenField <= 0 || lenField > maxMessageSize {
				break
			}
			total := 1 + lenField
			if rem < total {
				break
			}
			raw := make([]byte, total)
			copy(raw, remaining[:total])
			msgTs := stream.timestampForOffset(processed)
			var query string
			if first == 'Q' || first == 'P' {
				msgLen := lenField - 4
				if msgLen > 0 && len(remaining) >= 5+msgLen {
					query = extractNullTerminatedString(remaining[5 : 5+msgLen])
				}
			}
			messages = append(messages, models.PostgreSQLMessage{
				Timestamp:  msgTs,
				Query:      query,
				Type:       first,
				IPSource:   ipSrc,
				IPDest:     ipDst,
				PortSource: portSrc,
				PortDest:   portDst,
				Raw:        raw,
			})
			processed += total
			continue
		}

		// length-only (Startup/SSLRequest)
		lenField := int(binary.BigEndian.Uint32(remaining[0:4]))
		if lenField <= 0 || lenField > maxMessageSize {
			break
		}
		total := lenField
		if rem < total {
			break
		}
		raw := make([]byte, total)
		copy(raw, remaining[:total])
		msgTs := stream.timestampForOffset(processed)
		messages = append(messages, models.PostgreSQLMessage{
			Timestamp:  msgTs,
			Query:      "",
			Type:       0,
			IPSource:   ipSrc,
			IPDest:     ipDst,
			PortSource: portSrc,
			PortDest:   portDst,
			Raw:        raw,
		})
		processed += total
	}

	// сдвиг буфера и корректировка сегментов
	if processed > 0 {
		if processed >= len(stream.buffer) {
			stream.buffer = stream.buffer[:0]
			stream.segments = stream.segments[:0]
		} else {
			stream.buffer = stream.buffer[processed:]
			rem := processed
			newSegs := make([]segment, 0, len(stream.segments))
			for _, s := range stream.segments {
				if rem <= 0 {
					newSegs = append(newSegs, s)
					continue
				}
				if rem < s.length {
					s.length -= rem
					newSegs = append(newSegs, s)
					rem = 0
				} else {
					rem -= s.length
				}
			}
			stream.segments = newSegs
		}
	}
	return messages
}

// timestampForOffset возвращает время первого сегмента, содержащего байт с заданным смещением.
func (s *TCPStream) timestampForOffset(offset int) time.Time {
	if offset < 0 {
		return time.Time{}
	}
	acc := 0
	for _, seg := range s.segments {
		if offset < acc+seg.length {
			return seg.ts
		}
		acc += seg.length
	}
	return time.Time{}
}

// extractNullTerminatedString возвращает строку до первого нулевого байта.
func extractNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

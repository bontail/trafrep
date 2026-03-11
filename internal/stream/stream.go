package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	msgtypes "trafRep/internal/stream/message_types"
)

// PostgreSQLMessage представляет одно логическое сообщение PostgreSQL от клиента к серверу,
// объединённое из одного или нескольких TCP-сегментов.
type PostgreSQLMessage struct {
	FirstTCPPacketTimestamp time.Time
	LastTCPPacketTimestamp  time.Time
	Type                    msgtypes.ClientMessageType
	Len                     uint32
	Payload                 []byte
}

// TimeUntilSendFirstPacket возвращает продолжительность от pcapTime до момента отправки первого TCP-пакета сообщения.
func (m PostgreSQLMessage) TimeUntilSendFirstPacket(pcapTime time.Time) time.Duration {
	return m.FirstTCPPacketTimestamp.Sub(pcapTime)
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

// ServerMessage представляет одно логическое сообщение PostgreSQL от сервера к клиенту.
type ServerMessage struct {
	Timestamp time.Time
	Type      msgtypes.ServerMessageType
	Len       uint32
}

// TimelineMessage — объединённое представление клиентского или серверного сообщения для визуализации.
type TimelineMessage struct {
	Timestamp time.Time
	TypeName  string
	IsServer  bool
	QueryText string // текст SQL-запроса (только для Query-сообщений, иначе "")
}

// TCPStream хранит буферы и сегменты для двух направлений одного TCP-потока.
type TCPStream struct {
	clientBuf               []byte
	clientSegs              segments
	serverBuf               []byte
	serverSegs              segments
	serverProcessedMessages int
	completed               []PostgreSQLMessage
	serverCompleted         []ServerMessage
	HaveAllMessages         bool
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

// segments — срез записей о TCP-сегментах, составляющих одно направление потока.
type segments []segment

// timestampByOffset возвращает временну́ю метку сегмента, которому принадлежит байт с данным смещением.
// Если смещение выходит за пределы всех сегментов, возвращается нулевое время.
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
// сборку полных клиентских и серверных PostgreSQL‑сообщений из TCP-пакетов.
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

// allStreamsSorted возвращает все стримы (завершённые + активные), отсортированные
// по времени первого сообщения (клиентского или серверного — какое раньше).
func (m *TCPStreamManager) allStreamsSorted() []*TCPStream {
	streams := make([]*TCPStream, 0, len(m.completedStreams)+len(m.activeStreams))
	streams = append(streams, m.completedStreams...)
	for _, s := range m.activeStreams {
		streams = append(streams, s)
	}
	sort.Slice(streams, func(i, j int) bool {
		return streamFirstTimestamp(streams[i]).Before(streamFirstTimestamp(streams[j]))
	})
	return streams
}

// streamFirstTimestamp возвращает самую раннюю метку времени среди клиентских и серверных сообщений стрима.
func streamFirstTimestamp(s *TCPStream) time.Time {
	var t time.Time
	if len(s.completed) > 0 {
		t = s.completed[0].FirstTCPPacketTimestamp
	}
	if len(s.serverCompleted) > 0 {
		st := s.serverCompleted[0].Timestamp
		if t.IsZero() || st.Before(t) {
			t = st
		}
	}
	return t
}

// GetStreamMessages возвращает срез из срезов всех завершённых сообщений,
// отсортированных по времени первого сообщения в стриме.
func (m *TCPStreamManager) GetStreamMessages() [][]PostgreSQLMessage {
	var allMessages [][]PostgreSQLMessage
	for _, s := range m.allStreamsSorted() {
		allMessages = append(allMessages, s.completed)
	}
	return allMessages
}

// GetStreamServerMessages возвращает срез из срезов всех завершённых серверных сообщений,
// отсортированных по времени первого сообщения в стриме.
func (m *TCPStreamManager) GetStreamServerMessages() [][]ServerMessage {
	var allMessages [][]ServerMessage
	for _, s := range m.allStreamsSorted() {
		allMessages = append(allMessages, s.serverCompleted)
	}
	return allMessages
}

// GetStreamTimelines возвращает для каждого стрима объединённый список клиентских и серверных сообщений,
// отсортированный по времени.
func (m *TCPStreamManager) GetStreamTimelines() [][]TimelineMessage {
	clientStreams := m.GetStreamMessages()
	serverStreams := m.GetStreamServerMessages()

	count := len(clientStreams)
	if len(serverStreams) > count {
		count = len(serverStreams)
	}

	result := make([][]TimelineMessage, count)
	for i := 0; i < count; i++ {
		var timeline []TimelineMessage
		if i < len(clientStreams) {
			for _, msg := range clientStreams[i] {
				tm := TimelineMessage{
					Timestamp: msg.FirstTCPPacketTimestamp,
					TypeName:  msg.Type.String(),
					IsServer:  false,
				}
				if msg.Type.IsSimpleQuery() {
					tm.QueryText = msg.PrettyQuery()
				}
				timeline = append(timeline, tm)
			}
		}
		if i < len(serverStreams) {
			for _, msg := range serverStreams[i] {
				timeline = append(timeline, TimelineMessage{
					Timestamp: msg.Timestamp,
					TypeName:  msg.Type.String(),
					IsServer:  true,
				})
			}
		}
		sort.Slice(timeline, func(a, b int) bool {
			return timeline[a].Timestamp.Before(timeline[b].Timestamp)
		})
		result[i] = timeline
	}
	return result
}

// AddPacket добавляет один TCP-пакет в поток с идентификатором key.
// Данные от клиента накапливаются и из них извлекаются полные PostgreSQL‑сообщения, которые сохраняются в completed.
// Данные от сервера накапливаются и парсятся в серверные сообщения, которые сохраняются в serverCompleted.
func (m *TCPStreamManager) AddPacket(data []byte, timestamp time.Time, ipSrc, ipDst string, portSrc, portDst uint16, serverIp string, serverPort uint16) error {
	isFromServer := (ipSrc == serverIp || serverIp == "") && portSrc == serverPort

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
	if len(data) != 1 && msgtypes.IsSSLandGSSENCAnswer(data[0]) && len(data) < 5 && isFromServer && stream.canBeSSLandGSSENCAnswer() {
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

// canBeStartupMessage возвращает true, если следующее клиентское сообщение может быть StartupMessage.
// Это возможно в начале потока, а также после SSLRequest или GSSENCRequest.
func (s *TCPStream) canBeStartupMessage() bool {
	if len(s.completed) == 0 {
		return true
	}
	last := s.completed[len(s.completed)-1].Type
	return last == msgtypes.SSLRequest || last == msgtypes.GSSENCRequest
}

// canBeCipherMessage возвращает true, если следующее клиентское сообщение может быть SSLRequest или GSSENCRequest.
// SSLRequest и GSSENCRequest допустимы первым сообщением; после отказа одного из них допускается попробовать другой (§54.2.10–11).
func (s *TCPStream) canBeCipherMessage() bool {
	if len(s.completed) == 0 {
		return true
	}
	return len(s.completed) == 1 && s.completed[0].Type.IsCipherType()
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
	if len(s.clientBuf) < 5 {
		return PostgreSQLMessage{}, 0
	}
	dataLen := int(binary.BigEndian.Uint32(s.clientBuf[1:5]))
	if dataLen < 4 {
		return PostgreSQLMessage{}, 0
	}
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
			FirstTCPPacketTimestamp: msgFirstTs,
			LastTCPPacketTimestamp:  msgLastTs,
			Len:                     uint32(dataLen),
			Payload:                 payload,
			Type:                    s.clientMessageType(),
		},
		total
}

// tryCreateClientUntypedMessage пытается создать PostgreSQLMessage для сообщений без типа (только длина).
// Возвращает сообщение и число обработанных байт (0 если недостаточно данных).
func (s *TCPStream) tryCreateClientUntypedMessage() (msg PostgreSQLMessage, processed int) {
	remaining := s.clientBuf[:]
	dataLen := int(binary.BigEndian.Uint32(remaining[0:4]))
	if dataLen < 4 {
		return PostgreSQLMessage{}, 0
	}
	if len(s.clientBuf) < dataLen {
		return PostgreSQLMessage{}, 0
	}
	payloadLen := dataLen - 4
	payload := make([]byte, payloadLen)
	copy(payload, remaining[4:4+payloadLen])
	msgFirstTs := s.clientSegs.timestampByOffset(0)
	msgLastTs := s.clientSegs.timestampByOffset(dataLen - 1)
	return PostgreSQLMessage{
		FirstTCPPacketTimestamp: msgFirstTs,
		LastTCPPacketTimestamp:  msgLastTs,
		Len:                     uint32(dataLen),
		Payload:                 payload,
		Type:                    s.clientMessageType(),
	}, dataLen

}

// clearClientProcessedBytes удаляет из clientBuf первые processed байт и корректирует clientSegs.
// Полностью потреблённые сегменты удаляются; у частично потреблённого сегмента уменьшается length,
// чтобы timestampByOffset(0) для следующего сообщения возвращал правильную метку времени.
func (s *TCPStream) clearClientProcessedBytes(processed int) {
	s.clientBuf = s.clientBuf[processed:]
	remaining := uint32(processed)
	for len(s.clientSegs) > 0 {
		if s.clientSegs[0].length <= remaining {
			remaining -= s.clientSegs[0].length
			s.clientSegs = s.clientSegs[1:]
		} else {
			s.clientSegs[0].length -= remaining
			break
		}
	}
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
		s.completed = append(s.completed, msg)
		s.clearClientProcessedBytes(processed)
		if msgType == msgtypes.Terminate || msgType == msgtypes.CancelRequest {
			s.HaveAllMessages = true
			break
		}
	}
}

// tryReadServerMessage пытается прочитать сообщение от сервера.
// Возвращает распарсенное серверное сообщение и число обработанных байт (0 если недостаточно данных).
func (s *TCPStream) tryReadServerMessage() (msg ServerMessage, processed int) {
	ts := s.serverSegs.timestampByOffset(0)
	if s.canBeSSLandGSSENCAnswer() && msgtypes.IsSSLandGSSENCAnswer(s.serverBuf[0]) {
		return ServerMessage{Timestamp: ts, Type: msgtypes.SSLandGSSENCAnswer, Len: 1}, 1
	}
	if len(s.serverBuf) < 5 {
		return ServerMessage{}, 0
	}
	msgType := msgtypes.ServerMessageType(s.serverBuf[0])
	dataLen := int(binary.BigEndian.Uint32(s.serverBuf[1:5]))
	total := 1 + dataLen
	if len(s.serverBuf) < total {
		return ServerMessage{}, 0
	}
	return ServerMessage{Timestamp: ts, Type: msgType, Len: uint32(total)}, total
}

// clearServerProcessedBytes удаляет из serverBuf первые processed байт и корректирует serverSegs.
// Полностью потреблённые сегменты удаляются; у частично потреблённого сегмента уменьшается length.
func (s *TCPStream) clearServerProcessedBytes(processed int) {
	s.serverBuf = s.serverBuf[processed:]
	remaining := uint32(processed)
	for len(s.serverSegs) > 0 {
		if s.serverSegs[0].length <= remaining {
			remaining -= s.serverSegs[0].length
			s.serverSegs = s.serverSegs[1:]
		} else {
			s.serverSegs[0].length -= remaining
			break
		}
	}
}

// canBeSSLandGSSENCAnswer возвращает true, если сервер ещё не отправил ни одного сообщения,
// то есть ожидается однобайтовый SSL/GSSENC-ответ.
func (s *TCPStream) canBeSSLandGSSENCAnswer() bool {
	return s.serverProcessedMessages == 0
}

// parseServerBuffer считывает серверные сообщения из serverBuf, сохраняет их в serverCompleted
// и продвигает счётчик serverProcessedMessages для корректной идентификации однобайтового SSL/GSSENC-ответа.
func (s *TCPStream) parseServerBuffer() {
	for len(s.serverBuf) > 4 || s.canBeSSLandGSSENCAnswer() {
		msg, processed := s.tryReadServerMessage()
		if processed < 1 {
			break
		}
		s.serverCompleted = append(s.serverCompleted, msg)
		s.serverProcessedMessages++
		s.clearServerProcessedBytes(processed)
	}
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
	if msgtypes.IsCancelRequest(data) {
		return msgtypes.CancelRequest
	}
	if s.canBeStartupMessage() && !preliminaryType.IsNormalType() {
		return msgtypes.StartupMessage
	}
	return preliminaryType
}

// DivergeRange описывает один диапазон расхождения типов сообщений внутри стрима.
type DivergeRange struct {
	// Start — индекс первого расходящегося сообщения.
	Start int
	// End — индекс первого сообщения после расхождения, где типы совпали снова.
	// -1 означает расхождение до конца стрима.
	End int
	// LeftType / RightType — типы сообщений в начале диапазона.
	LeftType  string
	RightType string
}

// DivergeInfo описывает все диапазоны расхождения двух стримов по типам сообщений.
type DivergeInfo struct {
	// StreamIndex — номер стрима (0-based).
	StreamIndex int
	// Ranges — все найденные диапазоны расхождений. Пустой срез = стримы идентичны.
	Ranges []DivergeRange
}

// FindDivergeInfo сравнивает два набора таймлайнов (клиент+сервер) по типам сообщений.
// Для каждого стрима возвращает все диапазоны [Start, End) где типы расходятся.
func FindDivergeInfo(left, right [][]TimelineMessage) []DivergeInfo {
	count := len(left)
	if len(right) > count {
		count = len(right)
	}

	result := make([]DivergeInfo, count)
	for si := 0; si < count; si++ {
		info := DivergeInfo{StreamIndex: si}

		if si >= len(left) {
			leftType := ""
			if len(right[si]) > 0 {
				leftType = right[si][0].TypeName
			}
			info.Ranges = []DivergeRange{{Start: 0, End: -1, RightType: leftType}}
			result[si] = info
			continue
		}
		if si >= len(right) {
			rightType := ""
			if len(left[si]) > 0 {
				rightType = left[si][0].TypeName
			}
			info.Ranges = []DivergeRange{{Start: 0, End: -1, LeftType: rightType}}
			result[si] = info
			continue
		}

		l, r := left[si], right[si]
		minLen := len(l)
		if len(r) < minLen {
			minLen = len(r)
		}

		mi := 0
		for mi < minLen {
			// Ищем начало расхождения
			if l[mi].TypeName == r[mi].TypeName {
				mi++
				continue
			}
			rng := DivergeRange{
				Start:     mi,
				End:       -1,
				LeftType:  l[mi].TypeName,
				RightType: r[mi].TypeName,
			}
			// Ищем конец расхождения
			mi++
			for mi < minLen {
				if l[mi].TypeName == r[mi].TypeName {
					rng.End = mi
					break
				}
				mi++
			}
			info.Ranges = append(info.Ranges, rng)
			// Если нашли конец — продолжаем с этой же позиции (она уже совпала)
			// Если не нашли (End == -1) — выходим из цикла
			if rng.End < 0 {
				break
			}
		}

		// Если длины разные и в конце общей части всё совпало — добавляем диапазон "хвост"
		if len(l) != len(r) {
			// Проверяем: последний диапазон не закрыт до самого minLen
			lastCovered := 0
			if len(info.Ranges) > 0 {
				last := info.Ranges[len(info.Ranges)-1]
				if last.End < 0 {
					lastCovered = minLen // уже покрыто до конца
				} else {
					lastCovered = last.End
				}
			}
			if lastCovered <= minLen && minLen < max(len(l), len(r)) {
				leftType, rightType := "", ""
				if minLen < len(l) {
					leftType = l[minLen].TypeName
				} else {
					rightType = r[minLen].TypeName
				}
				info.Ranges = append(info.Ranges, DivergeRange{
					Start:     minLen,
					End:       -1,
					LeftType:  leftType,
					RightType: rightType,
				})
			}
		}

		result[si] = info
	}
	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

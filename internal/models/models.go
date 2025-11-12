package models

import (
	"encoding/binary"
	"time"
)

type ClientMessageType byte
type ServerMessageType byte

const (
	// client -> server
	MessageTypeQuery     ClientMessageType = 'Q'
	MessageTypeParse     ClientMessageType = 'P'
	MessageTypeBind      ClientMessageType = 'B'
	MessageTypeExecute   ClientMessageType = 'E'
	MessageTypeTerminate ClientMessageType = 'X'

	// server -> client
	MessageTypeCommandComplete ServerMessageType = 'C'
	MessageTypeReadyForQuery   ServerMessageType = 'Z'
	MessageTypeAuthRequest     ServerMessageType = 'R'
	MessageTypeErrorResponse   ServerMessageType = 'E'
	MessageTypeRowDescription  ServerMessageType = 'T'
	MessageTypeDataRow         ServerMessageType = 'D'
)

var clientMessageTypeNames = map[ClientMessageType]string{
	MessageTypeQuery:     "Query (Q)",
	MessageTypeParse:     "Parse (P)",
	MessageTypeBind:      "Bind (B)",
	MessageTypeExecute:   "Execute (E)",
	MessageTypeTerminate: "Terminate (X)",
}

var serverMessageTypeNames = map[ServerMessageType]string{
	MessageTypeCommandComplete: "CommandComplete (C)",
	MessageTypeReadyForQuery:   "ReadyForQuery (Z)",
	MessageTypeAuthRequest:     "Authentication (R)",
	MessageTypeErrorResponse:   "ErrorResponse (E)",
	MessageTypeRowDescription:  "RowDescription (T)",
	MessageTypeDataRow:         "DataRow (D)",
}

func (mt ClientMessageType) String() string {
	if s, ok := clientMessageTypeNames[mt]; ok {
		return s
	}
	if mt == 0 {
		return "<len-only>"
	}
	return string(byte(mt))
}

func (mt ClientMessageType) IsSimpleQuery() bool {
	return mt == MessageTypeQuery
}

func (mt ServerMessageType) String() string {
	if s, ok := serverMessageTypeNames[mt]; ok {
		return s
	}
	if mt == 0 {
		return "<len-only>"
	}
	return string(byte(mt))
}

// PostgreSQLMessage представляет одно логическое сообщение PostgreSQL от клиента к серверу,
// объединённое из одного или нескольких TCP-сегментов.
type PostgreSQLMessage struct {
	FirstTCPPacketTimestamp  time.Time
	LastTCPPacketTimestamp   time.Time
	CommandCompleteTimestamp time.Time
	Type                     ClientMessageType
	Len                      uint32
	Payload                  []byte
}

// Row возвращает байтовое представление сообщения в том виде, которое нужно отправлять.
func (m PostgreSQLMessage) Row() []byte {
	if m.Type != 0 {
		totalLen := 1 + m.Len
		buf := make([]byte, totalLen)
		buf[0] = byte(m.Type)
		binary.BigEndian.PutUint32(buf[1:5], m.Len)
		copy(buf[5:], m.Payload)
		return buf
	}
	buf := make([]byte, m.Len)
	binary.BigEndian.PutUint32(buf[0:4], m.Len)
	copy(buf[4:], m.Payload)
	return buf
}

type PostgresTCPPacket struct {
	Timestamp  time.Time
	Data       []byte
	IPSource   string
	IPDest     string
	PortSource uint16
	PortDest   uint16
}

type ReplayConfig struct {
	TargetHost string
	TargetPort int
	Rate       float64
	PrintQuery bool
	MaxRetries int
}

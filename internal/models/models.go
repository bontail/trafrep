package models

import "time"

// PostgreSQLMessage представляет одно логическое сообщение PostgreSQL,
// объединённое из одного или нескольких TCP-сегментов.
// Raw содержит оригинальные байты сообщения (type+len+body или length-only).
type PostgreSQLMessage struct {
	Timestamp  time.Time
	Query      string
	Type       byte
	IPSource   string
	IPDest     string
	PortSource uint16
	PortDest   uint16
	Raw        []byte
}

// TCPPacket представляет один захваченный TCP-пакет и его метаданные.
type TCPPacket struct {
	Timestamp    time.Time
	Data         []byte
	IPSource     string
	IPDest       string
	PortSource   uint16
	PortDest     uint16
	IsPostgreSQL bool
}

// ReplayConfig содержит настройки для воспроизведения сообщений.
type ReplayConfig struct {
	TargetHost  string
	TargetPort  int
	Rate        float64
	ExactTiming bool
}

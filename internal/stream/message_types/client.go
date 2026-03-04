package message_types

import (
	"bytes"
)

// ClientMessageType — тип байта, идентифицирующего PostgreSQL-сообщение от клиента к серверу.
type ClientMessageType byte

const (
	Query           ClientMessageType = 'Q'
	Parse           ClientMessageType = 'P'
	Bind            ClientMessageType = 'B'
	Execute         ClientMessageType = 'E'
	Sync            ClientMessageType = 'S'
	Terminate       ClientMessageType = 'X'
	CopyData        ClientMessageType = 'd'
	CopyDone        ClientMessageType = 'c'
	CopyFail        ClientMessageType = 'f'
	Describe        ClientMessageType = 'D'
	Flush           ClientMessageType = 'H'
	FunctionCall    ClientMessageType = 'F'
	PasswordMessage ClientMessageType = 'p'
	Close           ClientMessageType = 'C'

	// не имеют числовых значений, имеют отдельный формат сообщений без байта типа сообщения
	// значения выбраны из диапазона, который не пересекается с обычными типами сообщений
	StartupMessage ClientMessageType = 255
	SSLRequest     ClientMessageType = 254
	GSSENCRequest  ClientMessageType = 253
	CancelRequest  ClientMessageType = 252
)

// IsSSLRequest возвращает true, если data совпадает с фиксированной байтовой последовательностью SSLRequest (код 80877103).
func IsSSLRequest(data []byte) bool {
	return bytes.Equal(data, []byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F})
}

// IsGSSENCRequest возвращает true, если data совпадает с фиксированной байтовой последовательностью GSSENCRequest (код 80877104).
func IsGSSENCRequest(data []byte) bool {
	return bytes.Equal(data, []byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x30})
}

// IsCancelRequest возвращает true, если data начинается с фиксированной последовательности CancelRequest ( код 80877102).
func IsCancelRequest(data []byte) bool {
	return bytes.Equal(data, []byte{0, 0, 0, 0x10, 0x04, 0xD2, 0x16, 0x2E})
}

var clientMessageTypeNames = map[ClientMessageType]string{
	Query:           "Query",
	Parse:           "Parse",
	Bind:            "Bind",
	Execute:         "Execute",
	Sync:            "Sync",
	Terminate:       "Terminate",
	CopyData:        "CopyData",
	CopyDone:        "CopyDone",
	CopyFail:        "CopyFail",
	Describe:        "Describe",
	Flush:           "Flush",
	FunctionCall:    "FunctionCall",
	PasswordMessage: "PasswordMessage",
	StartupMessage:  "StartupMessage",
	SSLRequest:      "SSLRequest",
	GSSENCRequest:   "GSSENCRequest",
	CancelRequest:   "CancelRequest",
	Close:           "Close",
}

var waitedMessages = map[ClientMessageType]map[ServerMessageType]bool{
	Query: {
		ReadyForQuery: true,
	},
	StartupMessage: {
		ReadyForQuery: true,
	},
	Sync: {
		ReadyForQuery: true,
	},
	Execute: {
		CommandComplete:    true,
		PortalSuspended:    true,
		EmptyQueryResponse: true,
		ErrorResponse:      true,
	},
	FunctionCall: {
		ReadyForQuery: true,
	},
	SSLRequest: {
		SSLandGSSENCAnswer: true,
	},
	GSSENCRequest: {
		SSLandGSSENCAnswer: true,
	},
}

// String возвращает человекочитаемое имя типа клиентского сообщения.
func (mt ClientMessageType) String() string {
	if s, ok := clientMessageTypeNames[mt]; ok {
		return s
	}
	return "InvalidClientMessageType (" + string(mt) + ")"
}

// IsSimpleQuery возвращает true, если тип сообщения — Query (простой протокол запросов).
func (mt ClientMessageType) IsSimpleQuery() bool {
	return mt == Query
}

// IsNormalType возвращает true, если сообщение является обычным типизированным сообщением
// (имеет байт типа в начале), то есть не StartupMessage, SSLRequest, GSSENCRequest или CancelRequest.
func (mt ClientMessageType) IsNormalType() bool {
	_, ok := clientMessageTypeNames[mt]
	return ok &&
		mt != StartupMessage &&
		mt != SSLRequest &&
		mt != GSSENCRequest &&
		mt != CancelRequest
}

// NeedCommandCompleteAnswer возвращает true, если сервер должен ответить на данное сообщение CommandComplete.
func (mt ClientMessageType) NeedCommandCompleteAnswer() bool {
	return mt.NeedAnswers()[CommandComplete]
}

// NeedReadyForQueryAnswer возвращает true, если сервер должен ответить на данное сообщение ReadyForQuery.
func (mt ClientMessageType) NeedReadyForQueryAnswer() bool {
	return mt.NeedAnswers()[ReadyForQuery]
}

// NeedAnswers возвращает набор серверных сообщений, завершающих обработку данного клиентского сообщения.
// Пустой map означает, что ответ не ожидается.
func (mt ClientMessageType) NeedAnswers() map[ServerMessageType]bool {
	return waitedMessages[mt]
}

// IsCipherType возвращает true, если сообщение инициирует шифрование соединения (SSLRequest или GSSENCRequest).
func (mt ClientMessageType) IsCipherType() bool {
	return mt == SSLRequest || mt == GSSENCRequest
}

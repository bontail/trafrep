package message_types

import "reflect"

type ClientMessageType byte

const (
	Query           ClientMessageType = 'Q'
	Parse           ClientMessageType = 'P'
	Bind            ClientMessageType = 'B'
	Execute         ClientMessageType = 'E'
	Sync            ClientMessageType = 'S'
	Terminate       ClientMessageType = 'X'
	CopyData        ClientMessageType = 'd'
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

func IsSSLRequest(data []byte) bool {
	return reflect.DeepEqual(data, []byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F})
}

func IsGSSENCRequest(data []byte) bool {
	return reflect.DeepEqual(data, []byte{0, 0, 0, 8, 0x04, 0xB5, 0x54, 0x0B})
}

var clientMessageTypeNames = map[ClientMessageType]string{
	Query:           "Query",
	Parse:           "Parse",
	Bind:            "Bind",
	Execute:         "Execute",
	Sync:            "Sync",
	Terminate:       "Terminate",
	CopyData:        "CopyData",
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
		CommandComplete: true,
		ReadyForQuery:   true,
	},
	StartupMessage: {
		ReadyForQuery: true,
	},
	Sync: {
		ReadyForQuery: true,
	},
	Execute: {
		CommandComplete: true,
		ReadyForQuery:   true,
	},
	SSLRequest: {
		SSLandGSSENCAnswer: true,
	},
	GSSENCRequest: {
		SSLandGSSENCAnswer: true,
	},
}

func (mt ClientMessageType) String() string {
	if s, ok := clientMessageTypeNames[mt]; ok {
		return s
	}
	return "InvalidClientMessageType (" + string(mt) + ")"
}

func (mt ClientMessageType) IsSimpleQuery() bool {
	return mt == Query
}

func (mt ClientMessageType) IsNormalType() bool {
	_, ok := clientMessageTypeNames[mt]
	return ok &&
		mt != StartupMessage &&
		mt != SSLRequest &&
		mt != GSSENCRequest &&
		mt != CancelRequest
}

func (mt ClientMessageType) NeedCommandCompleteAnswer() bool {
	return mt.NeedAnswers()[CommandComplete]
}

func (mt ClientMessageType) NeedReadyForQueryAnswer() bool {
	return mt.NeedAnswers()[ReadyForQuery]
}

func (mt ClientMessageType) NeedAnswers() map[ServerMessageType]bool {
	return waitedMessages[mt]
}

func (mt ClientMessageType) IsCipherType() bool {
	return mt == SSLRequest || mt == GSSENCRequest
}

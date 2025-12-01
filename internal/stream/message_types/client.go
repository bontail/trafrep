package message_types

import "strings"

type ClientMessageType byte

const (
	Query            ClientMessageType = 'Q'
	Parse            ClientMessageType = 'P'
	Bind             ClientMessageType = 'B'
	Execute          ClientMessageType = 'E'
	Sync             ClientMessageType = 'S'
	Terminate        ClientMessageType = 'X'
	CopyData         ClientMessageType = 'd'
	CopyFail         ClientMessageType = 'f'
	Describe         ClientMessageType = 'D'
	Flush            ClientMessageType = 'H'
	FunctionCall     ClientMessageType = 'F'
	PasswordMessage  ClientMessageType = 'p'
	ClientOnlyLength ClientMessageType = 0
	StartMessage     ClientMessageType = 255 // стартовое сообщение не имеет числового значения,
	// значение выбрано случайно
)

var clientMessageTypeNames = map[ClientMessageType]string{
	Query:            "Query",
	Parse:            "Parse",
	Bind:             "Bind",
	Execute:          "Execute",
	Sync:             "Sync",
	Terminate:        "Terminate",
	CopyData:         "CopyData",
	CopyFail:         "CopyFail",
	Describe:         "CopyDescribe",
	Flush:            "Flush",
	FunctionCall:     "FunctionCall",
	PasswordMessage:  "PasswordMessage",
	ClientOnlyLength: "<len-only>",
}

var waitedMessages = map[ClientMessageType]map[ServerMessageType]bool{
	Query: {
		CommandComplete: true,
		ReadyForQuery:   true,
	},
	StartMessage: {
		ReadyForQuery: true,
	},
}

func (mt ClientMessageType) String() string {
	var sb strings.Builder
	if s, ok := clientMessageTypeNames[mt]; ok {
		sb.WriteString(s)
	}
	if mt.IsNormalType() {
		sb.WriteString(" (" + string(mt) + ")")
	}
	return sb.String()
}

func (mt ClientMessageType) IsSimpleQuery() bool {
	return mt == Query
}

func (mt ClientMessageType) IsNormalType() bool {
	_, ok := clientMessageTypeNames[mt]
	return mt != ClientOnlyLength && ok
}

func (mt ClientMessageType) NeedCommandCompleteAnswer() bool {
	return mt == Query
}

func (mt ClientMessageType) NeedReadyForQueryAnswer() bool {
	return mt == Query
}

func (mt ClientMessageType) NeedAnswers() map[ServerMessageType]bool {
	return waitedMessages[mt]
}

package message_types

import "strings"

type ClientMessageType byte

const (
	// MessageTypeQuery
	// client -> server
	MessageTypeQuery                ClientMessageType = 'Q'
	MessageTypeParse                ClientMessageType = 'P'
	MessageTypeBind                 ClientMessageType = 'B'
	MessageTypeExecute              ClientMessageType = 'E'
	MessageTypeSync                 ClientMessageType = 'S'
	MessageTypeTerminate            ClientMessageType = 'X'
	MessageTypeCopyData             ClientMessageType = 'd'
	MessageTypeCopyFail             ClientMessageType = 'f'
	MessageTypeDescribe             ClientMessageType = 'D'
	MessageTypeFlush                ClientMessageType = 'H'
	MessageTypeFunctionCall         ClientMessageType = 'F'
	MessageTypeFunctionCallResponse ClientMessageType = 'V'
	MessageTypePasswordMessage      ClientMessageType = 'p'
	ClientMessageTypeOnlyLength     ClientMessageType = 0 // для сообщений без типа, только с длиной
)

var clientMessageTypeNames = map[ClientMessageType]string{
	MessageTypeQuery:                "Query",
	MessageTypeParse:                "Parse",
	MessageTypeBind:                 "Bind",
	MessageTypeExecute:              "Execute",
	MessageTypeSync:                 "Sync",
	MessageTypeTerminate:            "Terminate",
	MessageTypeCopyData:             "CopyData",
	MessageTypeCopyFail:             "CopyFail",
	MessageTypeDescribe:             "CopyDescribe",
	MessageTypeFlush:                "Flush",
	MessageTypeFunctionCall:         "FunctionCall",
	MessageTypeFunctionCallResponse: "FunctionCallResponse",
	MessageTypePasswordMessage:      "PasswordMessage",
	ClientMessageTypeOnlyLength:     "<len-only>",
}

func (mt ClientMessageType) String() string {
	var sb strings.Builder
	if s, ok := clientMessageTypeNames[mt]; ok {
		sb.WriteString(s)
	}
	if mt.HaveTypeByte() {
		sb.WriteString(" (" + string(mt) + ")")
	}
	return sb.String()
}

func (mt ClientMessageType) IsSimpleQuery() bool {
	return mt == MessageTypeQuery
}

func (mt ClientMessageType) HaveTypeByte() bool {
	return mt != ClientMessageTypeOnlyLength
}

func (mt ClientMessageType) NeedCommandCompleteAnswer() bool {
	return mt == MessageTypeQuery
}

func (mt ClientMessageType) NeedReadyForQueryAnswer() bool {
	return mt == MessageTypeQuery
}

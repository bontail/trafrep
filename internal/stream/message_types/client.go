package message_types

import "strings"

type ClientMessageType byte

const (
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
	ClientMessageTypeOnlyLength     ClientMessageType = 0
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
	if mt.IsNormalType() {
		sb.WriteString(" (" + string(mt) + ")")
	}
	return sb.String()
}

func (mt ClientMessageType) IsSimpleQuery() bool {
	return mt == MessageTypeQuery
}

func (mt ClientMessageType) IsNormalType() bool {
	_, ok := clientMessageTypeNames[mt]
	return mt != ClientMessageTypeOnlyLength && ok
}

func (mt ClientMessageType) NeedCommandCompleteAnswer() bool {
	return mt == MessageTypeQuery
}

func (mt ClientMessageType) NeedReadyForQueryAnswer() bool {
	return mt == MessageTypeQuery
}

func (mt ClientMessageType) IsLastMessage() bool {
	return mt == MessageTypeTerminate
}

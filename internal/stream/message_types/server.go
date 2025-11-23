package message_types

type ServerMessageType byte

const (
	MessageTypeCommandComplete        ServerMessageType = 'C'
	MessageTypeReadyForQuery          ServerMessageType = 'Z'
	MessageTypeAuthRequest            ServerMessageType = 'R'
	MessageTypeErrorResponse          ServerMessageType = 'E'
	MessageTypeRowDescription         ServerMessageType = 'T'
	MessageTypeDataRow                ServerMessageType = 'D'
	ServerClientMessageTypeOnlyLength ServerMessageType = 0
)

var serverMessageTypeNames = map[ServerMessageType]string{
	MessageTypeCommandComplete:        "CommandComplete",
	MessageTypeReadyForQuery:          "ReadyForQuery",
	MessageTypeAuthRequest:            "Authentication",
	MessageTypeErrorResponse:          "ErrorResponse",
	MessageTypeRowDescription:         "RowDescription",
	MessageTypeDataRow:                "DataRow",
	ServerClientMessageTypeOnlyLength: "<len-only>",
}

func (mt ServerMessageType) String() string {
	if s, ok := serverMessageTypeNames[mt]; ok {
		return s
	}
	return string(mt)
}

func (mt ServerMessageType) IsCommandComplete() bool {
	return mt == MessageTypeCommandComplete
}

func (mt ServerMessageType) IsReadyForQuery() bool {
	return mt == MessageTypeReadyForQuery
}

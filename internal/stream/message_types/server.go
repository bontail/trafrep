package message_types

type ServerMessageType byte

const (
	MessageTypeCommandComplete  ServerMessageType = 'C'
	MessageTypeReadyForQuery    ServerMessageType = 'Z'
	MessageTypeAuthRequest      ServerMessageType = 'R'
	MessageTypeErrorResponse    ServerMessageType = 'E'
	MessageTypeRowDescription   ServerMessageType = 'T'
	MessageTypeDataRow          ServerMessageType = 'D'
	MessageTypeParameterStatus  ServerMessageType = 'S'
	MessageTypeBackendKeyData   ServerMessageType = 'K'
	ServerMessageTypeOnlyLength ServerMessageType = 0
)

var serverMessageTypeNames = map[ServerMessageType]string{
	MessageTypeCommandComplete:  "CommandComplete",
	MessageTypeReadyForQuery:    "ReadyForQuery",
	MessageTypeAuthRequest:      "Authentication",
	MessageTypeErrorResponse:    "ErrorResponse",
	MessageTypeRowDescription:   "RowDescription",
	MessageTypeDataRow:          "DataRow",
	MessageTypeParameterStatus:  "ParameterStatus",
	MessageTypeBackendKeyData:   "BackendKeyData",
	ServerMessageTypeOnlyLength: "<len-only>",
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

func (mt ServerMessageType) IsNormalType() bool {
	_, ok := serverMessageTypeNames[mt]
	return mt != ServerMessageTypeOnlyLength && ok
}

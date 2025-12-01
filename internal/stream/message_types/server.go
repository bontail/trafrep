package message_types

type ServerMessageType byte

const (
	CommandComplete      ServerMessageType = 'C'
	ReadyForQuery        ServerMessageType = 'Z'
	AuthenticationOK     ServerMessageType = 'R'
	ErrorResponse        ServerMessageType = 'E'
	RowDescription       ServerMessageType = 'T'
	DataRow              ServerMessageType = 'D'
	ParameterStatus      ServerMessageType = 'S'
	BackendKeyData       ServerMessageType = 'K'
	FunctionCallResponse ServerMessageType = 'V'
	ServerOnlyLength     ServerMessageType = 0
)

var serverMessageTypeNames = map[ServerMessageType]string{
	CommandComplete:      "CommandComplete",
	ReadyForQuery:        "ReadyForQuery",
	AuthenticationOK:     "Authentication",
	ErrorResponse:        "ErrorResponse",
	RowDescription:       "RowDescription",
	DataRow:              "DataRow",
	ParameterStatus:      "ParameterStatus",
	BackendKeyData:       "BackendKeyData",
	FunctionCallResponse: "FunctionCallResponse",
	ServerOnlyLength:     "<len-only>",
}

func (mt ServerMessageType) String() string {
	if s, ok := serverMessageTypeNames[mt]; ok {
		return s
	}
	return string(mt)
}

func (mt ServerMessageType) IsCommandComplete() bool {
	return mt == CommandComplete
}

func (mt ServerMessageType) IsReadyForQuery() bool {
	return mt == ReadyForQuery
}

func (mt ServerMessageType) IsNormalType() bool {
	_, ok := serverMessageTypeNames[mt]
	return mt != ServerOnlyLength && ok
}

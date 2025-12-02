package message_types

type ServerMessageType byte

const (
	CommandComplete          ServerMessageType = 'C'
	ReadyForQuery            ServerMessageType = 'Z'
	AuthenticationOK         ServerMessageType = 'R'
	ErrorResponse            ServerMessageType = 'E'
	RowDescription           ServerMessageType = 'T'
	DataRow                  ServerMessageType = 'D'
	ParameterStatus          ServerMessageType = 'S'
	BackendKeyData           ServerMessageType = 'K'
	FunctionCallResponse     ServerMessageType = 'V'
	NegotiateProtocolVersion ServerMessageType = 'v'
	ParseComplete            ServerMessageType = '1'
	BindComplete             ServerMessageType = '2'
	CloseComplete            ServerMessageType = '3'
	PortalSuspended          ServerMessageType = 's'
	CopyInResponse           ServerMessageType = 'G'
	CopyOutResponse          ServerMessageType = 'H'
	CopyBothResponse         ServerMessageType = 'W'
	EmptyQueryResponse       ServerMessageType = 'I'
	NoData                   ServerMessageType = 'n'
	NoticeResponse           ServerMessageType = 'N'
	NotificationResponse     ServerMessageType = 'A'
	ParameterDescription     ServerMessageType = 't'
	ServerOnlyLength         ServerMessageType = 0
)

var serverMessageTypeNames = map[ServerMessageType]string{
	CommandComplete:          "CommandComplete",
	ReadyForQuery:            "ReadyForQuery",
	AuthenticationOK:         "Authentication",
	ErrorResponse:            "ErrorResponse",
	RowDescription:           "RowDescription",
	DataRow:                  "DataRow",
	ParameterStatus:          "ParameterStatus",
	BackendKeyData:           "BackendKeyData",
	FunctionCallResponse:     "FunctionCallResponse",
	NegotiateProtocolVersion: "NegotiateProtocolVersion",
	ParseComplete:            "ParseComplete",
	BindComplete:             "BindComplete",
	CloseComplete:            "CloseComplete",
	PortalSuspended:          "PortalSuspended",
	CopyInResponse:           "CopyInResponse",
	CopyOutResponse:          "CopyOutResponse",
	CopyBothResponse:         "CopyBothResponse",
	EmptyQueryResponse:       "EmptyQueryResponse",
	NoData:                   "NoData",
	NoticeResponse:           "NoticeResponse",
	NotificationResponse:     "NotificationResponse",
	ParameterDescription:     "ParameterDescription",
	ServerOnlyLength:         "<len-only>",
}

func (mt ServerMessageType) String() string {
	if s, ok := serverMessageTypeNames[mt]; ok {
		return s
	}
	return serverMessageTypeNames[ServerOnlyLength]
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

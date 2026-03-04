package message_types

// ServerMessageType — тип байта, идентифицирующего PostgreSQL-сообщение от сервера к клиенту.
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
	SSLandGSSENCAnswer       ServerMessageType = 0
)

// SSLandGSSENAnswers содержит допустимые однобайтовые ответы сервера на SSLRequest и GSSENCRequest.
var SSLandGSSENAnswers = map[byte]bool{
	'S': true,
	'G': true,
	'N': true,
}

// IsSSLandGSSENCAnswer возвращает true, если b является однобайтовым ответом сервера
// на SSLRequest или GSSENCRequest ('S' — SSL поддерживается, 'N' — нет, 'G' — GSSENC поддерживается).
func IsSSLandGSSENCAnswer(b byte) bool {
	_, ok := SSLandGSSENAnswers[b]
	return ok
}

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
	SSLandGSSENCAnswer:       "SSLandGSSENCAnswer",
}

// String возвращает человекочитаемое имя типа серверного сообщения.
func (mt ServerMessageType) String() string {
	if s, ok := serverMessageTypeNames[mt]; ok {
		return s
	}
	return "InvalidServerMessageType (" + string(mt) + ")"
}

// IsCommandComplete возвращает true, если тип сообщения — CommandComplete.
func (mt ServerMessageType) IsCommandComplete() bool {
	return mt == CommandComplete
}

// IsReadyForQuery возвращает true, если тип сообщения — ReadyForQuery.
func (mt ServerMessageType) IsReadyForQuery() bool {
	return mt == ReadyForQuery
}

// IsNormalType возвращает true, если сообщение является обычным типизированным сообщением
// (не является специальным однобайтовым SSL/GSSENC-ответом).
func (mt ServerMessageType) IsNormalType() bool {
	_, ok := serverMessageTypeNames[mt]
	return ok &&
		mt != SSLandGSSENCAnswer
}

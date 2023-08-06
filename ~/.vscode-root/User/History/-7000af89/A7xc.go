package models

type MySQLPacketHeader struct {
	PacketLength uint32 `json:"packet_length" yaml:"packet_length"`
	PacketNumber uint8  `json:"packet_number" yaml:"packet_number"`
}
type MySQLRequest struct {
	Header    *MySQLPacketHeader `json:"header" yaml:"header"`
	Message   interface{}        `json:"message" yaml:"message"`
	ReadDelay int64              `json:"read_delay,omitempty"`
}

type MySQLResponse struct {
	Header    *MySQLPacketHeader `json:"header" yaml:"header"`
	Message   interface{}        `json:"message" yaml:"message"`
	ReadDelay int64              `json:"read_delay,omitempty"`
}

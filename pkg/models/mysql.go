package models

import (
	"gopkg.in/yaml.v3"
)

type MySQLSpec struct {
	Metadata       map[string]string `json:"metadata" yaml:"metadata"`
	RequestHeader  MySQLPacketHeader `json:"request_mysql_header" yaml:"request_mysql_header"`
	ResponseHeader MySQLPacketHeader `json:"response_mysql_header" yaml:"response_mysql_header"`
	Request        yaml.Node         `json:"mysql_request" yaml:"mysql_request"`
	Response       yaml.Node         `json:"mysql_response" yaml:"mysql_response"`
}

type MySQLPacketHeader struct {
	PacketLength uint32 `json:"packet_length" yaml:"packet_length"`
	PacketNumber uint8  `json:"packet_number" yaml:"packet_number"`
}

type MySQLRequest struct {
	Command  byte   `json:"command" yaml:"command"`
	Argument string `json:"argument" yaml:"argument"`
}

type MySQLResponse struct {
	PacketType    string `json:"packet_type" yaml:"packet_type"`
	PacketPayload string `json:"packet_payload" yaml:"packet_payload"`
}

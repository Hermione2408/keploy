package mysqlparser

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

type MySQLPacketHeader struct {
	PayloadLength uint32 // MySQL packet payload length
	SequenceID    uint8  // MySQL packet sequence ID
}

type HandshakeV10Packet struct {
	ProtocolVersion uint8
	ServerVersion   string
	ConnectionID    uint32
	AuthPluginData  []byte
	CapabilityFlags uint32
	CharacterSet    uint8
	StatusFlags     uint16
	AuthPluginName  string
}

type QueryPacket struct {
	Command byte
	Query   string
}

type OKPacket struct {
	AffectedRows uint64
	LastInsertID uint64
	StatusFlags  uint16
	Warnings     uint16
	Info         string
}

type EOFPacket struct {
	Header      byte
	Warnings    uint16
	StatusFlags uint16
}

type ERRPacket struct {
	Header         byte
	ErrorCode      uint16
	SQLStateMarker string
	SQLState       string
	ErrorMessage   string
}

type MySQLPacket struct {
	Header  MySQLPacketHeader
	Payload []byte
}

const (
	MaxPacketSize = 1<<24 - 1
)

type CapabilityFlags uint32

const (
	CLIENT_LONG_PASSWORD CapabilityFlags = 1 << iota
	CLIENT_FOUND_ROWS
	CLIENT_LONG_FLAG
	CLIENT_CONNECT_WITH_DB
	CLIENT_NO_SCHEMA
	CLIENT_COMPRESS
	CLIENT_ODBC
	CLIENT_LOCAL_FILES
	CLIENT_IGNORE_SPACE
	CLIENT_PROTOCOL_41
	CLIENT_INTERACTIVE
	CLIENT_SSL = 0x00000800
	CLIENT_IGNORE_SIGPIPE
	CLIENT_TRANSACTIONS
	CLIENT_RESERVED
	CLIENT_SECURE_CONNECTION
	CLIENT_MULTI_STATEMENTS = 1 << (iota + 2)
	CLIENT_MULTI_RESULTS
	CLIENT_PS_MULTI_RESULTS
	CLIENT_PLUGIN_AUTH
	CLIENT_CONNECT_ATTRS
	CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
	CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
	CLIENT_SESSION_TRACK
	CLIENT_DEPRECATE_EOF
)

type HandshakeResponse41 struct {
	CapabilityFlags   CapabilityFlags
	MaxPacketSize     uint32
	CharacterSet      uint8
	Reserved          [23]byte
	Username          string
	LengthEncodedInt  uint8
	AuthResponse      []byte
	Database          string
	AuthPluginName    string
	ConnectAttributes map[string]string
}

func NewHandshakeResponsePacket(handshake *HandshakeV10Packet, authMethod string, password string) *HandshakeResponse41 {
	authResponse := GenerateAuthResponse(password, handshake.AuthPluginData)
	return &HandshakeResponse41{
		CapabilityFlags: CapabilityFlags(handshake.CapabilityFlags),
		MaxPacketSize:   MaxPacketSize,
		CharacterSet:    0x21, // utf8_general_ci
		Username:        "user",
		AuthResponse:    authResponse,
		Database:        "shorturl_db",
		AuthPluginName:  authMethod,
	}
}
func GenerateAuthResponse(password string, salt []byte) []byte {
	// 1. Hash the password
	passwordHash := sha1.Sum([]byte(password))

	// 2. Hash the salt and the password hash
	finalHash := sha1.Sum(append(salt, passwordHash[:]...))

	return finalHash[:]
}

func (p *HandshakeResponse41) EncodeHandshake() ([]byte, error) {
	length := 4 + 4 + 1 + 23 + len(p.Username) + 1 + 1 + len(p.AuthResponse) + len(p.Database) + 1 + len(p.AuthPluginName) + 1
	buffer := make([]byte, length)
	offset := 0

	binary.LittleEndian.PutUint32(buffer[offset:], uint32(p.CapabilityFlags))
	offset += 4
	binary.LittleEndian.PutUint32(buffer[offset:], p.MaxPacketSize)
	offset += 4
	buffer[offset] = p.CharacterSet
	offset += 1 + 23
	offset += copy(buffer[offset:], p.Username)
	buffer[offset] = 0x00
	offset++
	buffer[offset] = uint8(len(p.AuthResponse))
	offset++
	offset += copy(buffer[offset:], p.AuthResponse)
	offset += copy(buffer[offset:], p.Database)
	buffer[offset] = 0x00
	offset++
	offset += copy(buffer[offset:], p.AuthPluginName)
	buffer[offset] = 0x00

	return buffer, nil
}

type SSLRequestPacket struct {
	Capabilities  uint32
	MaxPacketSize uint32
	CharacterSet  uint8
	Reserved      [23]byte
}

func NewSSLRequestPacket(capabilities uint32, maxPacketSize uint32, characterSet uint8) *SSLRequestPacket {
	// Ensure the SSL capability flag is set
	capabilities |= CLIENT_SSL

	if characterSet == 0 {
		characterSet = 33 // Set default to utf8mb4 if not specified.
	}

	return &SSLRequestPacket{
		Capabilities:  capabilities,
		MaxPacketSize: maxPacketSize,
		CharacterSet:  characterSet,
		Reserved:      [23]byte{},
	}
}

func (p *SSLRequestPacket) Encode() ([]byte, error) {
	buffer := new(bytes.Buffer)

	err := binary.Write(buffer, binary.LittleEndian, p.Capabilities)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buffer, binary.LittleEndian, p.MaxPacketSize)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buffer, binary.LittleEndian, p.CharacterSet)
	if err != nil {
		return nil, err
	}

	_, err = buffer.Write(p.Reserved[:])
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
func DecodeMySQLPacket(data []byte) (string, MySQLPacketHeader, interface{}, error) {
	header, err := decodeMySQLPacketHeader(data)
	if err != nil {
		return "", MySQLPacketHeader{}, nil, err
	}

	data = data[4:]

	var packet interface{}
	var packetType string

	switch {
	case data[0] == 0x0A:
		packetType = "MySQLHandshakeV10"
		packet, err = decodeMySQLHandshakeV10(data)
	case data[0] == 0x03:
		packetType = "MySQLQuery"
		packet, err = decodeMySQLQuery(data)
	case data[0] == 0x00:
		packetType = "MySQLOK"
		packet, err = decodeMySQLOK(data)
	case data[0] == 0xFF:
		packetType = "MySQLErr"
		packet, err = decodeMySQLErr(data)
	default:
		err = fmt.Errorf("unknown packet type: %v", data[0])
	}

	if err != nil {
		return "", MySQLPacketHeader{}, nil, err
	}

	return packetType, header, packet, nil
}

func decodeMySQLPacketHeader(data []byte) (MySQLPacketHeader, error) {
	if len(data) < 4 {
		return MySQLPacketHeader{}, fmt.Errorf("data too short")
	}

	length := binary.LittleEndian.Uint32(data[:4])
	sequenceID := data[3]

	return MySQLPacketHeader{PayloadLength: length, SequenceID: sequenceID}, nil
}

func decodeMySQLHandshakeV10(data []byte) (*HandshakeV10Packet, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("handshake packet too short")
	}

	packet := &HandshakeV10Packet{}
	packet.ProtocolVersion = data[0]

	idx := bytes.IndexByte(data[1:], 0x00)
	if idx == -1 {
		return nil, fmt.Errorf("malformed handshake packet: missing null terminator for ServerVersion")
	}
	packet.ServerVersion = string(data[1 : 1+idx])
	data = data[1+idx+1:]

	packet.ConnectionID = binary.LittleEndian.Uint32(data)
	data = data[4:]

	packet.AuthPluginData = data[:8]
	data = data[8:]

	data = data[1:]

	if len(data) < 4 {
		return nil, fmt.Errorf("handshake packet too short")
	}
	packet.CapabilityFlags = binary.LittleEndian.Uint32(data)
	data = data[4:]

	packet.CharacterSet = data[0]
	data = data[1:]

	packet.StatusFlags = binary.LittleEndian.Uint16(data)
	data = data[2:]

	authPluginDataLen := int(data[0])
	data = data[1:]

	data = data[10:]

	packet.AuthPluginData = append(packet.AuthPluginData, data[:authPluginDataLen-8]...)
	data = data[authPluginDataLen-8:]

	data = data[1:]

	idx = bytes.IndexByte(data, 0x00)
	if idx == -1 {
		return nil, fmt.Errorf("malformed handshake packet: missing null terminator for AuthPluginName")
	}
	packet.AuthPluginName = string(data[:idx])

	return packet, nil
}
func (packet *HandshakeV10Packet) ShouldUseSSL() bool {
	return (packet.CapabilityFlags & CLIENT_SSL) != 0
}

func (packet *HandshakeV10Packet) GetAuthMethod() string {
	// It will return the auth method
	return packet.AuthPluginName
}

func decodeMySQLQuery(data []byte) (*QueryPacket, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("query packet too short")
	}

	packet := &QueryPacket{}
	packet.Command = data[0]
	packet.Query = string(data[1:])

	return packet, nil
}

func decodeLengthEncodedInteger(b []byte) (value uint64, isNull bool, n int, err error) {
	if len(b) == 0 {
		return 0, false, 0, fmt.Errorf("buffer is empty")
	}

	switch {
	case b[0] < 0xfb:
		return uint64(b[0]), false, 1, nil
	case b[0] == 0xfc:
		if len(b) < 3 {
			return 0, false, 0, fmt.Errorf("not enough bytes to decode 2 byte integer")
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), false, 3, nil
	case b[0] == 0xfd:
		if len(b) < 4 {
			return 0, false, 0, fmt.Errorf("not enough bytes to decode 3 byte integer")
		}
		return uint64(binary.LittleEndian.Uint32(b[1:4]) & 0x00FFFFFF), false, 4, nil
	case b[0] == 0xfe:
		if len(b) < 9 {
			return 0, false, 0, fmt.Errorf("not enough bytes to decode 8 byte integer")
		}
		return binary.LittleEndian.Uint64(b[1:9]), false, 9, nil
	case b[0] == 0xff:
		return 0, true, 1, nil
	default:
		return 0, false, 0, fmt.Errorf("invalid length-encoded integer")
	}
}

func decodeMySQLOK(data []byte) (*OKPacket, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("OK packet too short")
	}

	packet := &OKPacket{}
	var isNull bool
	var err error
	var n int

	packet.AffectedRows, isNull, n, err = decodeLengthEncodedInteger(data)
	if err != nil || isNull {
		return nil, fmt.Errorf("failed to decode affected rows: %w", err)
	}
	data = data[n:]

	packet.LastInsertID, isNull, n, err = decodeLengthEncodedInteger(data)
	if err != nil || isNull {
		return nil, fmt.Errorf("failed to decode last insert ID: %w", err)
	}
	data = data[n:]

	if len(data) < 4 {
		return nil, fmt.Errorf("OK packet too short")
	}

	packet.StatusFlags = binary.LittleEndian.Uint16(data)
	data = data[2:]

	packet.Warnings = binary.LittleEndian.Uint16(data)
	data = data[2:]

	packet.Info = string(data)

	return packet, nil
}

func decodeMySQLErr(data []byte) (*ERRPacket, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("ERR packet too short")
	}
	if data[0] != 0xff {
		return nil, fmt.Errorf("invalid ERR packet header: %x", data[0])
	}

	packet := &ERRPacket{}
	packet.ErrorCode = binary.LittleEndian.Uint16(data[1:3])

	if data[3] != '#' {
		return nil, fmt.Errorf("invalid SQL state marker: %c", data[3])
	}
	packet.SQLState = string(data[4:9])
	packet.ErrorMessage = string(data[9:])
	return packet, nil
}

func decodeMYSQLEOF(data []byte) (*EOFPacket, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("EOF packet too short")
	}

	if data[0] != 0xfe {
		return nil, fmt.Errorf("invalid EOF packet header")
	}

	packet := &EOFPacket{}
	packet.Header = data[0]

	if len(data) >= 5 {
		packet.Warnings = binary.LittleEndian.Uint16(data[1:3])
		packet.StatusFlags = binary.LittleEndian.Uint16(data[3:5])
	}

	return packet, nil
}
func (p *MySQLPacket) Encode() ([]byte, error) {
	packet := make([]byte, 4+len(p.Payload))

	binary.LittleEndian.PutUint32(packet[:3], p.Header.PayloadLength)

	packet[3] = p.Header.SequenceID

	copy(packet[4:], p.Payload)

	return packet, nil
}

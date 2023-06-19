package mysqlparser

import (
	"bytes"
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

func DecodeMySQLPacket(data []byte) (string, MySQLPacketHeader, interface{}, error) {
	header, err := decodeMySQLPacketHeader(data)
	if err != nil {
		return "", MySQLPacketHeader{}, nil, err
	}

	data = data[4:] // Skip the 4-byte header

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
fmt.Println(len(data), data[:3])
// length := binary.LittleEndian.Uint32(data[:3])
lengthBytes := data[:3]
	length := int(uint32(lengthBytes[0]) | uint32(lengthBytes[1])<<8 | uint32(lengthBytes[2])<<16)
	sequenceID := data[3]

	return MySQLPacketHeader{PayloadLength: uint32(length), SequenceID: sequenceID}, nil
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

	packet.CapabilityFlags = uint32(binary.LittleEndian.Uint16(data))
	data = data[2:]

	packet.CharacterSet = data[0]
	data = data[1:]

	packet.StatusFlags = binary.LittleEndian.Uint16(data)
	data = data[2:]
	packet.CapabilityFlags |= uint32(binary.LittleEndian.Uint16(data)) << 16
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
		return 0, true, 1, nil // NULL is encoded as length byte 0xff
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

	// First byte is the header and should be 0xff
	if data[0] != 0xff {
		return nil, fmt.Errorf("invalid ERR packet header: %x", data[0])
	}

	packet := &ERRPacket{}
	packet.ErrorCode = binary.LittleEndian.Uint16(data[1:3])

	// SQL state marker and SQL state code
	if data[3] != '#' {
		return nil, fmt.Errorf("invalid SQL state marker: %c", data[3])
	}
	packet.SQLState = string(data[4:9])

	// The error message is the rest of the packet
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

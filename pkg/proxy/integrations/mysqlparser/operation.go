package mysqlparser

import (
	"bytes"
	"crypto/sha1"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
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
type PacketType2 struct {
	Field1 byte
	Field2 byte
	Field3 byte
}

func decodePacketType2(data []byte) (*PacketType2, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("PacketType2 too short")
	}

	return &PacketType2{
		Field1: data[0],
		Field2: data[1],
		Field3: data[2],
	}, nil
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

func (p *MySQLPacket) Encode() ([]byte, error) {
	packet := make([]byte, 4)

	binary.LittleEndian.PutUint32(packet[:3], p.Header.PayloadLength)
	packet[3] = p.Header.SequenceID

	// Simplistic interpretation of MySQL's COM_QUERY
	if p.Payload[0] == 0x03 {
		query := string(p.Payload[1:])
		queryObj := map[string]interface{}{
			"command": "COM_QUERY",
			"query":   query,
		}
		queryJson, _ := json.Marshal(queryObj)
		packet = append(packet, queryJson...)
	}

	return packet, nil
}

func DecodeMySQLPacket(packet MySQLPacket, logger *zap.Logger, destConn net.Conn) (string, MySQLPacketHeader, interface{}, error) {
	data := packet.Payload

	// Directly use the header from the packet
	header := packet.Header

	var packetData interface{}
	var packetType string
	var err error

	switch {
	case data[0] == 0x0e: // COM_PING
		packetType = "COM_PING"
		packetData, err = decodeComPing(data)
	case data[0] == 0x17: // COM_STMT_EXECUTE
		packetType = "COM_STMT_EXECUTE"
		packetData, err = decodeComStmtExecute(data)
	case data[0] == 0x16: // COM_STMT_FETCH
		packetType = "COM_STMT_FETCH"
		packetData, err = decodeComStmtFetch(data)
	case data[0] == 0x11: // COM_CHANGE_USER
		packetType = "COM_CHANGE_USER"
		packetData, err = decodeComChangeUser(data)
	case data[0] == 0x04: // Result Set Packet (First byte 0x04 may indicate a length-encoded integer, which is common in result set packets)
		fmt.Print("\n Result Set Packet \n", data)
		packetType = "Result Set Packet"
		packetData, err = DecodeResultSet(data, destConn)
	case data[0] == 0x0A:
		packetType = "MySQLHandshakeV10"
		packetData, err = decodeMySQLHandshakeV10(data)
	case data[0] == 0x03:
		packetType = "MySQLQuery"
		packetData, err = decodeMySQLQuery(data)
	case data[0] == 0x00:
		packetType = "MySQLOK"
		packetData, err = decodeMySQLOK(data)
	case data[0] == 0xFF:
		packetType = "MySQLErr"
		packetData, err = decodeMySQLErr(data)
	case data[0] == 0xFE: // EOF packet
		packetType = "MySQLEOF"
		packetData, err = decodeMYSQLEOF(data)
	case data[0] == 0x02: // New packet type
		packetType = "MySQLOK"
		packetData, err = decodePacketType2(data)
	case data[0] == 0x19: // New case for packet type 25
		packetType = "Control/Ping_Packet"
		packetData = nil
	default:
		packetType = "Unknown"
		packetData = data
		logger.Warn("unknown packet type", zap.Int("unknownPacketTypeInt", int(data[0])))
	}

	if err != nil {
		return "", MySQLPacketHeader{}, nil, err
	}

	return packetType, header, packetData, nil
}

type RowDataPacket struct {
	Data []byte
}

func readLengthEncodedInteger(b []byte) (uint64, bool, int) {
	if len(b) == 0 {
		return 0, true, 1
	}
	switch b[0] {
	case 0xfb:
		return 0, true, 1
	case 0xfc:
		return uint64(b[1]) | uint64(b[2])<<8, false, 3
	case 0xfd:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, false, 4
	case 0xfe:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 |
				uint64(b[4])<<24 | uint64(b[5])<<32 | uint64(b[6])<<40 |
				uint64(b[7])<<48 | uint64(b[8])<<56,
			false, 9
	default:
		return uint64(b[0]), false, 1
	}
}

func readLengthEncodedStringUpdated(data []byte) (string, []byte, error) {
	// First, determine the length of the string
	strLength, isNull, bytesRead := readLengthEncodedInteger(data)
	if isNull {
		return "", nil, errors.New("NULL value encountered")
	}

	// Adjust data to point to the next bytes after the integer
	data = data[bytesRead:]

	// Check if we have enough data left to read the string
	if len(data) < int(strLength) {
		return "", nil, errors.New("not enough data to read string")
	}

	// Read the string
	strData := data[:strLength]
	remainingData := data[strLength:]

	// Convert the byte array to a string
	str := string(strData)

	return str, remainingData, nil
}

func decodeRowData(data []byte, columns []ColumnDefinition) ([]RowDataPacket, []byte, error) {
	var rowPackets []RowDataPacket
	for _, _ = range columns {
		var rowData RowDataPacket
		var err error

		// Check for NULL column
		if data[0] == 0xfb {
			data = data[1:]
			rowData.Data = nil
			rowPackets = append(rowPackets, rowData)
			continue
		}

		var fieldStr string
		fieldStr, data, err = readLengthEncodedStringUpdated(data)
		if err != nil {
			return nil, nil, err
		}

		rowData.Data = []byte(fieldStr)
		rowPackets = append(rowPackets, rowData)
	}

	return rowPackets, data, nil
}

// func decodeColumnDefinition(data []byte) (*ColumnDefinition, []byte, error) {
// 	columnDef := &ColumnDefinition{}
// 	var err error

// 	// Parse each field from the column definition packet
// 	columnDef.catalog, data, err = readLengthEncodedStringUpdated(data)
// 	if err != nil {
// 		return nil, data, err
// 	}

// 	columnDef.schema, data, err = readLengthEncodedStringUpdated(data)
// 	if err != nil {
// 		return nil, data, err
// 	}

// 	columnDef.table, data, err = readLengthEncodedStringUpdated(data)
// 	if err != nil {
// 		return nil, data, err
// 	}

// 	columnDef.orgTable, data, err = readLengthEncodedStringUpdated(data)
// 	if err != nil {
// 		return nil, data, err
// 	}

// 	columnDef.name, data, err = readLengthEncodedStringUpdated(data)
// 	if err != nil {
// 		return nil, data, err
// 	}

// 	columnDef.orgName, data, err = readLengthEncodedStringUpdated(data)
// 	if err != nil {
// 		return nil, data, err
// 	}

// 	// Skip the next length value
// 	if len(data) < 1 {
// 		return nil, data, errors.New("data too short")
// 	}
// 	data = data[1:]

// 	columnDef.characterSet = binary.LittleEndian.Uint16(data[0:2])
// 	data = data[2:]

// 	columnDef.columnLength = binary.LittleEndian.Uint32(data[0:4])
// 	data = data[4:]

// 	columnDef.columnType = data[0]
// 	data = data[1:]

// 	columnDef.flags = binary.LittleEndian.Uint16(data[0:2])
// 	data = data[2:]

// 	columnDef.decimals = data[0]
// 	data = data[1:]

// 	// Skip filler
// 	data = data[2:]

// 	return columnDef, data, nil
// }

type OKPacket struct {
	AffectedRows uint64
	LastInsertID uint64
	StatusFlags  uint16
	Warnings     uint16
	Info         string
}
type ResultSet struct {
	ColumnCount       int
	ColumnDefinitions []ColumnDefinition
	Rows              [][]string
}

func decodeOKPacket(data []byte) (OKPacket, []byte, error) {
	var okPacket OKPacket
	if data[0] != 0xfe {
		return okPacket, data, errors.New("invalid OK packet")
	}

	// 0xfe is followed by affectedRows and lastInsertID
	var bytesRead int
	okPacket.AffectedRows, _, bytesRead = readLengthEncodedInteger(data[1:])
	data = data[bytesRead+1:]

	okPacket.LastInsertID, _, bytesRead = readLengthEncodedInteger(data)
	data = data[bytesRead:]

	if len(data) < 4 {
		return okPacket, data, errors.New("invalid OK packet")
	}

	// Then statusFlags and warnings
	okPacket.StatusFlags = binary.LittleEndian.Uint16(data)
	okPacket.Warnings = binary.LittleEndian.Uint16(data[2:])

	data = data[4:]

	// If more data, it's info message
	if len(data) > 0 {
		okPacket.Info, data, _ = readLengthEncodedStringUpdated(data)
	}

	return okPacket, data, nil
}

const (
	HeaderSize         = 1024
	OKPacketResulSet   = 0x00
	EOFPacketResultSet = 0xfe
	LengthEncodedInt   = 0xfb
)

// ColumnValue represents a value from a column in a result set
type ColumnValue struct {
	Null  bool
	Value string
}

type ColumnDefinition struct {
	Catalog      string
	Schema       string
	Table        string
	OrgTable     string
	Name         string
	OrgName      string
	Charset      uint16
	ColumnLength uint32
	Type         byte
	Flags        uint16
	Decimals     byte
}

const (
	iOK                = 0x00
	iERR               = 0xff
	iLocalInFile       = 0xfb
	iEOF          byte = 0xfe
	fieldTypeNULL      = iota
	fieldTypeTiny
	fieldTypeShort
	fieldTypeYear
	fieldTypeInt24
	fieldTypeLong
	fieldTypeLongLong
	fieldTypeFloat
	fieldTypeDouble
	fieldTypeDecimal
	fieldTypeNewDecimal
	fieldTypeVarChar
	fieldTypeBit
	fieldTypeEnum
	fieldTypeSet
	fieldTypeTinyBLOB
	fieldTypeMediumBLOB
	fieldTypeLongBLOB
	fieldTypeBLOB
	fieldTypeVarString
	fieldTypeString
	fieldTypeGeometry
	fieldTypeJSON
	fieldTypeDate
	fieldTypeNewDate
	fieldTypeTime
	fieldTypeTimestamp
	fieldTypeDateTime
	flagUnsigned
	statusMoreResultsExists
)

type packetDecoder struct {
	conn   net.Conn
	status statusFlag
}
type binaryRows struct {
	pd      *packetDecoder
	rs      resultSet
	mc      mysqlConn
	data    []byte
	columns []mysqlField
}

type resultSet struct {
	columns []column
	done    bool
}

type column struct {
	fieldType int
	flags     int
	decimals  int
}

type mysqlConn struct {
	status uint16
	cfg    config
}

type config struct {
	Loc int
}

var (
	ErrMalformPkt = errors.New("malformed packet")
)

// func sendPacket(data []byte) error {
// 	_, err := Write(data)
// 	if err != nil {
// 		return fmt.Errorf("error sending packet: %v", err)
// 	}
// 	return nil
// }

func handleOkPacket(data []byte) error {
	// OK packets start with 0x00
	if len(data) == 0 || data[0] != 0x00 {
		return fmt.Errorf("not an OK packet")
	}
	return nil
}

func handleErrorPacket(data []byte) error {
	errorCode := binary.LittleEndian.Uint16(data[1:3])
	sqlState := string(data[4:9])
	errorMessage := string(data[9:])
	return fmt.Errorf("Received error packet: error code %d, SQL state %s, error message %s", errorCode, sqlState, errorMessage)
}

func ReadLengthEncodedString(b []byte) ([]byte, bool, int, error) {
	// Get length
	num, isNull, n := ReadLengthEncodedInteger(b)
	if num < 1 {
		return b[n:n], isNull, n, nil
	}

	n += int(num)

	// Check data length
	if len(b) >= n {
		return b[n-int(num) : n : n], false, n, nil
	}
	return nil, false, n, io.EOF
}

// returns the number of bytes skipped and an error, in case the string is
// longer than the input slice
func skipLengthEncodedString(b []byte) (int, error) {
	// Get length
	num, _, n := readLengthEncodedInteger(b)
	if num < 1 {
		return n, nil
	}

	n += int(num)

	// Check data length
	if len(b) >= n {
		return n, nil
	}
	return n, io.EOF
}

// returns the number read, whether the value is NULL and the number of bytes read
func ReadLengthEncodedInteger(b []byte) (uint64, bool, int) {
	if len(b) == 0 {
		return 0, true, 1
	}

	switch b[0] {
	// 251: NULL
	case 0xfb:
		return 0, true, 1

	// 252: value of following 2
	case 0xfc:
		return uint64(b[1]) | uint64(b[2])<<8, false, 3

	// 253: value of following 3
	case 0xfd:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, false, 4

	// 254: value of following 8
	case 0xfe:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 |
				uint64(b[4])<<24 | uint64(b[5])<<32 | uint64(b[6])<<40 |
				uint64(b[7])<<48 | uint64(b[8])<<56,
			false, 9
	}

	// 0-250: value of first byte
	return uint64(b[0]), false, 1
}

// func handleInFileRequest(filename string) error {
// 	file, err := os.Open(filename)
// 	if err != nil {
// 		return err
// 	}
// 	defer file.Close()
// 	// Send the file content in packets of 4096 bytes
// 	buf := make([]byte, 4096)
// 	for {
// 		n, err := file.Read(buf)
// 		if err != nil {
// 			if err == io.EOF {
// 				break
// 			}
// 			return err
// 		}
// 		err = sendPacket(buf[:n])
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

func readResultSetHeaderPacket(data []byte) (int, error) {
	switch data[0] {
	case iOK:
		return 0, handleOkPacket(data)
	case iERR:
		return 0, handleErrorPacket(data)
		// case iLocalInFile:
		// 	return 0, handleInFileRequest(string(data[1:]))
	}

	// column count
	num, _, n := ReadLengthEncodedInteger(data)
	if n <= len(data) {
		return int(num), nil
	}
	return 0, ErrMalformPkt
}

type fieldType byte
type fieldFlag uint16
type mysqlField struct {
	tableName string
	name      string
	length    uint32
	flags     fieldFlag
	fieldType fieldType
	decimals  byte
	charSet   uint8
}

func readColumns(data []byte, count int) ([]mysqlField, error) {
	columns := make([]mysqlField, count)

	var pos int
	for i := 0; i < count; i++ {

		// EOF Packet
		if data[pos] == iEOF && (len(data[pos:]) == 5 || len(data[pos:]) == 1) {
			if i == count {
				return columns, nil
			}
			return nil, fmt.Errorf("column count mismatch n:%d len:%d", count, len(columns))
		}

		var n int
		var err error

		// Catalog
		pos, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}

		// Database [len coded string]
		n, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		// Table [len coded string]
		var tableName []byte
		tableName, _, n, err = ReadLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		columns[i].tableName = string(tableName)

		// Original table [len coded string]
		n, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		// Name [len coded string]
		var name []byte
		name, _, n, err = ReadLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		columns[i].name = string(name)
		pos += n

		// Original name [len coded string]
		n, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		// Filler [uint8]
		pos++

		// Charset [charset, collation uint8]
		columns[i].charSet = data[pos]
		pos += 2

		// Length [uint32]
		columns[i].length = binary.LittleEndian.Uint32(data[pos : pos+4])
		pos += 4

		// Field type [uint8]
		columns[i].fieldType = fieldType(data[pos])
		pos++

		// Flags [uint16]
		columns[i].flags = fieldFlag(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2

		// Decimals [uint8]
		columns[i].decimals = data[pos]
		pos++
	}

	return columns, nil
}

func (rows *binaryRows) HasNextResultSet() (b bool) {
	if rows.pd == nil {
		return false
	}
	return rows.mc.status&statusMoreResultsExists != 0
}

type statusFlag uint16

func readStatus(b []byte) statusFlag {
	return statusFlag(b[0]) | statusFlag(b[1])<<8
}
func uint64ToString(n uint64) []byte {
	var a [20]byte
	i := 20

	// U+0030 = 0
	// ...
	// U+0039 = 9

	var q uint64
	for n >= 10 {
		i--
		q = n / 10
		a[i] = uint8(n-q*10) + 0x30
		n = q
	}

	i--
	a[i] = uint8(n) + 0x30

	return a[i:]
}

func readRow(data []byte, dest []driver.Value, columns []mysqlField) error {
	var err error
	// packet indicator [1 byte]
	if data[0] != iOK {
		// EOF Packet
		if data[0] == iEOF && len(data) == 5 {
			return io.EOF
		}

		// Error otherwise
		return handleErrorPacket(data)
	}

	// NULL-bitmap,  [(column-count + 7 + 2) / 8 bytes]
	pos := 1 + (len(dest)+7+2)>>3
	nullMask := data[1:pos]

	for i := range dest {
		// Field is NULL
		// (byte >> bit-pos) % 2 == 1
		if ((nullMask[(i+2)>>3] >> uint((i+2)&7)) & 1) == 1 {
			dest[i] = nil
			continue
		}

		// Convert to byte-coded string
		switch columns[i].fieldType {
		case fieldTypeNULL:
			dest[i] = nil
			continue

		// Numeric Types
		case fieldTypeTiny:
			if columns[i].flags&flagUnsigned != 0 {
				dest[i] = int64(data[pos])
			} else {
				dest[i] = int64(int8(data[pos]))
			}
			pos++
			continue

		case fieldTypeShort, fieldTypeYear:
			if columns[i].flags&flagUnsigned != 0 {
				dest[i] = int64(binary.LittleEndian.Uint16(data[pos : pos+2]))
			} else {
				dest[i] = int64(int16(binary.LittleEndian.Uint16(data[pos : pos+2])))
			}
			pos += 2
			continue

		case fieldTypeInt24, fieldTypeLong:
			if columns[i].flags&flagUnsigned != 0 {
				dest[i] = int64(binary.LittleEndian.Uint32(data[pos : pos+4]))
			} else {
				dest[i] = int64(int32(binary.LittleEndian.Uint32(data[pos : pos+4])))
			}
			pos += 4
			continue

		case fieldTypeLongLong:
			if columns[i].flags&flagUnsigned != 0 {
				val := binary.LittleEndian.Uint64(data[pos : pos+8])
				if val > math.MaxInt64 {
					dest[i] = uint64ToString(val)
				} else {
					dest[i] = int64(val)
				}
			} else {
				dest[i] = int64(binary.LittleEndian.Uint64(data[pos : pos+8]))
			}
			pos += 8
			continue

		case fieldTypeFloat:
			dest[i] = math.Float32frombits(binary.LittleEndian.Uint32(data[pos : pos+4]))
			pos += 4
			continue

		case fieldTypeDouble:
			dest[i] = math.Float64frombits(binary.LittleEndian.Uint64(data[pos : pos+8]))
			pos += 8
			continue

		// Length coded Binary Strings
		case fieldTypeDecimal, fieldTypeNewDecimal, fieldTypeVarChar,
			fieldTypeBit, fieldTypeEnum, fieldTypeSet, fieldTypeTinyBLOB,
			fieldTypeMediumBLOB, fieldTypeLongBLOB, fieldTypeBLOB,
			fieldTypeVarString, fieldTypeString, fieldTypeGeometry, fieldTypeJSON:
			var isNull bool
			var n int
			dest[i], isNull, n, err = ReadLengthEncodedString(data[pos:])
			pos += n
			if err == nil {
				if !isNull {
					continue
				} else {
					dest[i] = nil
					continue
				}
			}
			return err

		case
			fieldTypeDate, fieldTypeNewDate, // Date YYYY-MM-DD
			fieldTypeTime,                         // Time [-][H]HH:MM:SS[.fractal]
			fieldTypeTimestamp, fieldTypeDateTime: // Timestamp YYYY-MM-DD HH:MM:SS[.fractal]

			num, _, n := ReadLengthEncodedInteger(data[pos:])
			pos += n

			if err == nil {
				pos += int(num)
				continue
			} else {
				return err
			}
		default:
			return fmt.Errorf("unknown field type %d", columns[i].fieldType)
		}
	}

	return nil
}

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
func (pd *packetDecoder) getData() ([]byte, error) {
	// Define a buffer to read the data into
	buf := make([]byte, 4096) // Choose an appropriate size

	// Read the data from the connection
	n, err := pd.conn.Read(buf)
	if err != nil {
		// Handle the error
		return nil, err
	}

	// Return the read data
	return buf[:n], nil
}

func (pd *packetDecoder) readPacket() ([]byte, error) {
	var buf [4]byte
	if _, err := io.ReadFull(pd.conn, buf[:]); err != nil {
		return nil, err
	}
	length := int(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16)
	data := make([]byte, length)
	if _, err := io.ReadFull(pd.conn, data); err != nil {
		return nil, err
	}
	return data, nil
}
func DecodeResultSet(data []byte, destConn net.Conn) ([][]driver.Value, error) {

	num, err := readResultSetHeaderPacket(data)
	if err != nil {
		return nil, err
	}

	// Read columns
	columns, err := readColumns(data, num)
	if err != nil {
		return nil, err
	}

	var rows [][]driver.Value

	for {
		// Prepare row
		row := make([]driver.Value, len(columns))

		// Read row
		err = readRow(data, row, columns)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		rows = append(rows, row)
	}

	return rows, nil
}

type byteConn struct {
	buffer *bytes.Buffer
}

func (c *byteConn) Read(b []byte) (n int, err error) {
	return c.buffer.Read(b)
}

func (c *byteConn) Write(b []byte) (n int, err error) {
	return 0, nil
}

func (c *byteConn) Close() error {
	return nil
}

func (c *byteConn) LocalAddr() net.Addr {
	return nil
}

func (c *byteConn) RemoteAddr() net.Addr {
	return nil
}

func (c *byteConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *byteConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *byteConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func newByteConn(data []byte) net.Conn {
	return &byteConn{
		buffer: bytes.NewBuffer(data),
	}
}

func decodeComStatistics(data []byte) (string, error) {
	if len(data) < 4 {
		return "", errors.New("Data too short for COM_STATISTICS")
	}

	// Get the string length from the first 3 bytes (length-encoded)
	strLen := int(binary.LittleEndian.Uint32(append(data[:3], 0)))
	//fmt.Printf("Data: %d\n", data) // Debug output

	//fmt.Printf("Decoded length: %d\n", strLen) // Debug output

	if len(data) < 4+strLen {
		return "", errors.New("Data too short for COM_STATISTICS")
	}

	// Extract the string data
	statisticsData := data[4 : 4+strLen]

	// Convert to string
	statistics := string(statisticsData)

	//fmt.Printf("Decoded string: '%s'\n", statistics) // Debug output

	return statistics, nil
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
func Uint24(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
}
func decodeLengthEncodedString(data []byte) (string, error) {
	if len(data) < 1 {
		return "", errors.New("data too short")
	}

	// Get the length of the string
	var length uint64
	switch data[0] {
	case 0xfb:
		return "", nil
	case 0xfc:
		if len(data) < 3 {
			return "", errors.New("data too short for 2-byte length")
		}
		length = uint64(binary.LittleEndian.Uint16(data[1:3]))
		data = data[3:]
	case 0xfd:
		if len(data) < 4 {
			return "", errors.New("data too short for 3-byte length")
		}
		length = uint64(Uint24(data[1:4]))
		data = data[4:]
	case 0xfe:
		if len(data) < 9 {
			return "", errors.New("data too short for 8-byte length")
		}
		length = binary.LittleEndian.Uint64(data[1:9])
		data = data[9:]
	default:
		length = uint64(data[0])
		data = data[1:]
	}

	// Get the string
	if uint64(len(data)) < length {
		return "", errors.New("data too short for string")
	}
	s := string(data[:length])

	return s, nil
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

	// Check if the data is a length-encoded string or ASCII numbers
	if data[0] <= 250 {
		// Length-encoded string
		packet.Info, err = decodeLengthEncodedString(data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode info: %w", err)
		}
	} else {
		// ASCII numbers
		packet.Info = string(data)
	}

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

type ComStmtFetchPacket struct {
	StatementID uint32
	RowCount    uint32
	Info        string
}

func decodeComStmtFetch(data []byte) (ComStmtFetchPacket, error) {
	if len(data) < 9 {
		return ComStmtFetchPacket{}, errors.New("Data too short for COM_STMT_FETCH")
	}

	statementID := binary.LittleEndian.Uint32(data[1:5])
	rowCount := binary.LittleEndian.Uint32(data[5:9])

	// Assuming the info starts at the 10th byte
	infoData := data[9:]
	info := string(infoData)

	return ComStmtFetchPacket{
		StatementID: statementID,
		RowCount:    rowCount,
		Info:        info,
	}, nil
}

type ComStmtExecute struct {
	StatementID    uint32
	Flags          byte
	IterationCount uint32
	NullBitmap     []byte
	ParamCount     uint16
	Parameters     []BoundParameter
}

type BoundParameter struct {
	Type     byte
	Unsigned byte
	Value    []byte
}

func decodeComStmtExecute(packet []byte) (ComStmtExecute, error) {
	// removed the print statement for cleanliness
	if len(packet) < 14 { // the minimal size of the packet without parameters should be 14, not 13
		return ComStmtExecute{}, fmt.Errorf("packet length less than 14 bytes")
	}

	stmtExecute := ComStmtExecute{}
	stmtExecute.StatementID = binary.LittleEndian.Uint32(packet[1:5])
	stmtExecute.Flags = packet[5]
	stmtExecute.IterationCount = binary.LittleEndian.Uint32(packet[6:10])

	// the next bytes are reserved for the Null-Bitmap, Parameter Bound Flag and Bound Parameters if they exist
	// if the length of the packet is greater than 14, then there are parameters
	if len(packet) > 14 {
		nullBitmapLength := int((stmtExecute.ParamCount + 7) / 8)

		stmtExecute.NullBitmap = packet[10 : 10+nullBitmapLength]
		stmtExecute.ParamCount = binary.LittleEndian.Uint16(packet[10+nullBitmapLength:])

		// in case new parameters are bound, the new types and values are sent
		if packet[10+nullBitmapLength] == 1 {
			// read the types and values of the new parameters
			stmtExecute.Parameters = make([]BoundParameter, stmtExecute.ParamCount)
			for i := 0; i < int(stmtExecute.ParamCount); i++ {
				index := 10 + nullBitmapLength + 1 + 2*i
				if index+1 >= len(packet) {
					return ComStmtExecute{}, fmt.Errorf("packet length less than expected while reading parameters")
				}
				stmtExecute.Parameters[i].Type = packet[index]
				stmtExecute.Parameters[i].Unsigned = packet[index+1]
			}
		}
	}

	return stmtExecute, nil
}

type ComChangeUserPacket struct {
	User         string
	Auth         []byte
	Db           string
	CharacterSet uint8
	AuthPlugin   string
}

func decodeComChangeUser(data []byte) (ComChangeUserPacket, error) {
	if len(data) < 2 {
		return ComChangeUserPacket{}, errors.New("Data too short for COM_CHANGE_USER")
	}

	nullTerminatedStrings := strings.Split(string(data[1:]), "\x00")
	if len(nullTerminatedStrings) < 5 {
		return ComChangeUserPacket{}, errors.New("Data malformed for COM_CHANGE_USER")
	}

	user := nullTerminatedStrings[0]
	authLength := data[len(user)+2]
	auth := data[len(user)+3 : len(user)+3+int(authLength)]
	db := nullTerminatedStrings[2]
	characterSet := data[len(user)+4+int(authLength)]
	authPlugin := nullTerminatedStrings[3]

	return ComChangeUserPacket{
		User:         user,
		Auth:         auth,
		Db:           db,
		CharacterSet: characterSet,
		AuthPlugin:   authPlugin,
	}, nil
}

type ComPingPacket struct {
}

func decodeComPing(data []byte) (ComPingPacket, error) {
	if len(data) < 1 || data[0] != 0x0e {
		return ComPingPacket{}, errors.New("Data malformed for COM_PING")
	}

	return ComPingPacket{}, nil
}

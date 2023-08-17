package mysqlparser

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.keploy.io/server/pkg/models"
	"go.uber.org/zap"
)

type MySQLPacketHeader struct {
	PayloadLength uint32 `yaml:"payload_length"` // MySQL packet payload length
	SequenceID    uint8  `yaml:"sequence_id"`    // MySQL packet sequence ID
}

type HandshakeV10Packet struct {
	ProtocolVersion uint8  `yaml:"protocol_version"`
	ServerVersion   string `yaml:"server_version"`
	ConnectionID    uint32 `yaml:"connection_id"`
	AuthPluginData  []byte `yaml:"auth_plugin_data"`
	CapabilityFlags uint32 `yaml:"capability_flags"`
	CharacterSet    uint8  `yaml:"character_set"`
	StatusFlags     uint16 `yaml:"status_flags"`
	AuthPluginName  string `yaml:"auth_plugin_name"`
}

type QueryPacket struct {
	Command byte   `yaml:"command"`
	Query   string `yaml:"query"`
}

type EOFPacket struct {
	Header      byte   `yaml:"header"`
	Warnings    uint16 `yaml:"warnings"`
	StatusFlags uint16 `yaml:"status_flags"`
}

type ERRPacket struct {
	Header         byte   `yaml:"header"`
	ErrorCode      uint16 `yaml:"error_code"`
	SQLStateMarker string `yaml:"sql_state_marker"`
	SQLState       string `yaml:"sql_state"`
	ErrorMessage   string `yaml:"error_message"`
}

type MySQLPacket struct {
	Header  MySQLPacketHeader `yaml:"header"`
	Payload []byte            `yaml:"payload"`
}

type HandshakeResponse41 struct {
	CapabilityFlags   CapabilityFlags   `yaml:"capability_flags"`
	MaxPacketSize     uint32            `yaml:"max_packet_size"`
	CharacterSet      uint8             `yaml:"character_set"`
	Reserved          [23]byte          `yaml:"reserved"`
	Username          string            `yaml:"username"`
	LengthEncodedInt  uint8             `yaml:"length_encoded_int"`
	AuthResponse      []byte            `yaml:"auth_response"`
	Database          string            `yaml:"database"`
	AuthPluginName    string            `yaml:"auth_plugin_name"`
	ConnectAttributes map[string]string `yaml:"connect_attributes"`
}

type PacketType2 struct {
	Field1 byte `yaml:"field1"`
	Field2 byte `yaml:"field2"`
	Field3 byte `yaml:"field3"`
}

type SSLRequestPacket struct {
	Capabilities  uint32   `yaml:"capabilities"`
	MaxPacketSize uint32   `yaml:"max_packet_size"`
	CharacterSet  uint8    `yaml:"character_set"`
	Reserved      [23]byte `yaml:"reserved"`
}

type StmtPrepareOk struct {
	Status       byte   `yaml:"status"`
	StatementID  uint32 `yaml:"statement_id"`
	NumColumns   uint16 `yaml:"num_columns"`
	NumParams    uint16 `yaml:"num_params"`
	WarningCount uint16 `yaml:"warning_count"`
}

type AuthSwitchRequest struct {
	PluginName string `yaml:"plugin_name"`
	Data       []byte `yaml:"data"`
}

type RowDataPacket struct {
	Data []byte `yaml:"data"`
}

type ResultSet struct {
	Columns []*ColumnDefinitionPacket `yaml:"columns"`
	Rows    []*Row                    `yaml:"rows"`
}

type ColumnValue struct {
	Null  bool   `yaml:"null"`
	Value string `yaml:"value"`
}

type ColumnDefinition struct {
	Catalog      string `yaml:"catalog"`
	Schema       string `yaml:"schema"`
	Table        string `yaml:"table"`
	OrgTable     string `yaml:"org_table"`
	Name         string `yaml:"name"`
	OrgName      string `yaml:"org_name"`
	Charset      uint16 `yaml:"charset"`
	ColumnLength uint32 `yaml:"column_length"`
	Type         byte   `yaml:"type"`
	Flags        uint16 `yaml:"flags"`
	Decimals     byte   `yaml:"decimals"`
}

type packetDecoder struct {
	conn net.Conn `yaml:"conn"`
}

type binaryRows struct {
	pd      *packetDecoder `yaml:"pd"`
	rs      resultSet      `yaml:"rs"`
	mc      mysqlConn      `yaml:"mc"`
	data    []byte         `yaml:"data"`
	columns []mysqlField   `yaml:"columns"`
}

type resultSet struct {
	columns []column `yaml:"columns"`
	done    bool     `yaml:"done"`
}

type column struct {
	fieldType int `yaml:"field_type"`
	flags     int `yaml:"flags"`
	decimals  int `yaml:"decimals"`
}

type mysqlConn struct {
	status uint16 `yaml:"status"`
	cfg    config `yaml:"cfg"`
}

type config struct {
	Loc int `yaml:"loc"`
}

type mysqlField struct {
	tableName string    `yaml:"table_name"`
	name      string    `yaml:"name"`
	length    uint32    `yaml:"length"`
	flags     fieldFlag `yaml:"flags"`
	fieldType fieldType `yaml:"field_type"`
	decimals  byte      `yaml:"decimals"`
	charSet   uint8     `yaml:"char_set"`
}

type Row struct {
	Columns map[string]interface{} `yaml:"columns"`
}

type ColumnDefinitionPacket struct {
	Catalog      string `yaml:"catalog"`
	Schema       string `yaml:"schema"`
	Table        string `yaml:"table"`
	OrgTable     string `yaml:"org_table"`
	Name         string `yaml:"name"`
	OrgName      string `yaml:"org_name"`
	CharacterSet uint16 `yaml:"character_set"`
	ColumnLength uint32 `yaml:"column_length"`
	ColumnType   string `yaml:"column_type"`
	Flags        uint16 `yaml:"flags"`
	Decimals     uint8  `yaml:"decimals"`
	Filler       uint16 `yaml:"filler"`
	DefaultValue string `yaml:"default_value"`
}

type ResultsetRowPacket struct {
	ColumnValues []string `yaml:"column_values"`
	RowValues    []string `yaml:"row_values"`
}

type ComStmtFetchPacket struct {
	StatementID uint32 `yaml:"statement_id"`
	RowCount    uint32 `yaml:"row_count"`
	Info        string `yaml:"info"`
}

type ComStmtExecute struct {
	StatementID    uint32           `yaml:"statement_id"`
	Flags          byte             `yaml:"flags"`
	IterationCount uint32           `yaml:"iteration_count"`
	NullBitmap     []byte           `yaml:"null_bitmap"`
	ParamCount     uint16           `yaml:"param_count"`
	Parameters     []BoundParameter `yaml:"parameters"`
}

type BoundParameter struct {
	Type     byte   `yaml:"type"`
	Unsigned byte   `yaml:"unsigned"`
	Value    []byte `yaml:"value"`
}

type ComChangeUserPacket struct {
	User         string `yaml:"user"`
	Auth         []byte `yaml:"auth"`
	Db           string `yaml:"db"`
	CharacterSet uint8  `yaml:"character_set"`
	AuthPlugin   string `yaml:"auth_plugin"`
}

type COM_STMT_SEND_LONG_DATA struct {
	StatementID uint32 `yaml:"statement_id"`
	ParameterID uint16 `yaml:"parameter_id"`
	Data        []byte `yaml:"data"`
}

type COM_STMT_RESET struct {
	StatementID uint32 `yaml:"statement_id"`
}

type PluginDetails struct {
	Type    string `yaml:"type"`
	Message string `yaml:"message"`
}

type HandshakeResponse struct {
	CapabilityFlags uint32   `yaml:"capability_flags"`
	MaxPacketSize   uint32   `yaml:"max_packet_size"`
	CharacterSet    uint8    `yaml:"character_set"`
	Reserved        [23]byte `yaml:"reserved"`
	Username        string   `yaml:"username"`
	AuthData        []byte   `yaml:"auth_data"`
	Database        string   `yaml:"database"`
	AuthPluginName  string   `yaml:"auth_plugin_name"`
}

type HandshakeResponseOk struct {
	PacketIndicator string        `yaml:"packet_indicator"`
	PluginDetails   PluginDetails `yaml:"plugin_details"`
	RemainingBytes  []byte        `yaml:"remaining_bytes"`
}
type ComStmtPreparePacket struct {
	Query string
}
type ComStmtClosePacket struct {
	StatementID uint32
}

const (
	iAuthMoreData                                byte = 0x01
	cachingSha2PasswordRequestPublicKey               = 2
	cachingSha2PasswordFastAuthSuccess                = 3
	cachingSha2PasswordPerformFullAuthentication      = 4
)

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

var mySQLfieldTypeNames = map[byte]string{
	0x00: "MYSQL_TYPE_DECIMAL",
	0x01: "MYSQL_TYPE_TINY",
	0x02: "MYSQL_TYPE_SHORT",
	0x03: "MYSQL_TYPE_LONG",
	0x04: "MYSQL_TYPE_FLOAT",
	0x05: "MYSQL_TYPE_DOUBLE",
	0x06: "MYSQL_TYPE_NULL",
	0x07: "MYSQL_TYPE_TIMESTAMP",
	0x08: "MYSQL_TYPE_LONGLONG",
	0x09: "MYSQL_TYPE_INT24",
	0x0a: "MYSQL_TYPE_DATE",
	0x0b: "MYSQL_TYPE_TIME",
	0x0c: "MYSQL_TYPE_DATETIME",
	0x0d: "MYSQL_TYPE_YEAR",
	0x0e: "MYSQL_TYPE_NEWDATE",
	0x0f: "MYSQL_TYPE_VARCHAR",
	0x10: "MYSQL_TYPE_BIT",
	0xf6: "MYSQL_TYPE_NEWDECIMAL",
	0xf7: "MYSQL_TYPE_ENUM",
	0xf8: "MYSQL_TYPE_SET",
	0xf9: "MYSQL_TYPE_TINY_BLOB",
	0xfa: "MYSQL_TYPE_MEDIUM_BLOB",
	0xfb: "MYSQL_TYPE_LONG_BLOB",
	0xfc: "MYSQL_TYPE_BLOB",
	0xfd: "MYSQL_TYPE_VAR_STRING",
	0xfe: "MYSQL_TYPE_STRING",
	0xff: "MYSQL_TYPE_GEOMETRY",
}
var columnTypeValues = map[string]byte{
	"MYSQL_TYPE_DECIMAL":     0x00,
	"MYSQL_TYPE_TINY":        0x01,
	"MYSQL_TYPE_SHORT":       0x02,
	"MYSQL_TYPE_LONG":        0x03,
	"MYSQL_TYPE_FLOAT":       0x04,
	"MYSQL_TYPE_DOUBLE":      0x05,
	"MYSQL_TYPE_NULL":        0x06,
	"MYSQL_TYPE_TIMESTAMP":   0x07,
	"MYSQL_TYPE_LONGLONG":    0x08,
	"MYSQL_TYPE_INT24":       0x09,
	"MYSQL_TYPE_DATE":        0x0a,
	"MYSQL_TYPE_TIME":        0x0b,
	"MYSQL_TYPE_DATETIME":    0x0c,
	"MYSQL_TYPE_YEAR":        0x0d,
	"MYSQL_TYPE_NEWDATE":     0x0e,
	"MYSQL_TYPE_VARCHAR":     0x0f,
	"MYSQL_TYPE_BIT":         0x10,
	"MYSQL_TYPE_NEWDECIMAL":  0xf6,
	"MYSQL_TYPE_ENUM":        0xf7,
	"MYSQL_TYPE_SET":         0xf8,
	"MYSQL_TYPE_TINY_BLOB":   0xf9,
	"MYSQL_TYPE_MEDIUM_BLOB": 0xfa,
	"MYSQL_TYPE_LONG_BLOB":   0xfb,
	"MYSQL_TYPE_BLOB":        0xfc,
	"MYSQL_TYPE_VAR_STRING":  0xfd,
	"MYSQL_TYPE_STRING":      0xfe,
	"MYSQL_TYPE_GEOMETRY":    0xff,
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

var handshakePluginName string

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

var lastCommand byte // This is global and will remember the last command

func encodeHandshakePacket(packet *models.MySQLHandshakeV10Packet) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Protocol version
	buf.WriteByte(packet.ProtocolVersion)

	// Server version
	buf.WriteString(packet.ServerVersion)
	buf.WriteByte(0x00) // Null terminator

	// Connection ID
	binary.Write(buf, binary.LittleEndian, packet.ConnectionID)

	// Auth-plugin-data-part-1 (first 8 bytes)
	if len(packet.AuthPluginData) < 8 {
		return nil, errors.New("auth plugin data too short")
	}
	buf.Write(packet.AuthPluginData[:8])

	// Filler
	buf.WriteByte(0x00)

	// Lower 2 bytes of CapabilityFlags
	binary.Write(buf, binary.LittleEndian, uint16(packet.CapabilityFlags))

	// Character set
	buf.WriteByte(packet.CharacterSet)

	// Status flags
	binary.Write(buf, binary.LittleEndian, packet.StatusFlags)

	// Upper 2 bytes of CapabilityFlags
	binary.Write(buf, binary.LittleEndian, uint16(packet.CapabilityFlags>>16))

	// Length of auth-plugin-data (always 0x15 for the current version of the MySQL protocol)
	buf.WriteByte(0x15)

	// Reserved (10 zero bytes)
	buf.Write(make([]byte, 10))

	// Auth-plugin-data-part-2 (remaining auth data, 13 bytes, without the last byte)
	if len(packet.AuthPluginData) < 21 {
		return nil, errors.New("auth plugin data too short")
	}
	buf.Write(packet.AuthPluginData[8:20])

	// Null terminator for auth-plugin-data
	buf.WriteByte(0x00)

	// Auth-plugin name
	buf.WriteString(packet.AuthPluginName)
	buf.WriteByte(0x00) // Null terminator

	return buf.Bytes(), nil
}

func encodeLengthEncodedInteger(n uint64) []byte {
	var buf []byte

	if n <= 250 {
		buf = append(buf, byte(n))
	} else if n <= 0xffff {
		buf = append(buf, 0xfc, byte(n), byte(n>>8))
	} else if n <= 0xffffff {
		buf = append(buf, 0xfd, byte(n), byte(n>>8), byte(n>>16))
	} else {
		buf = append(buf, 0xfe, byte(n), byte(n>>8), byte(n>>16), byte(n>>24), byte(n>>32), byte(n>>40), byte(n>>48), byte(n>>56))
	}

	return buf
}

func encodeMySQLStmtPrepareOk(packet *models.MySQLStmtPrepareOk) ([]byte, error) {
	buf := new(bytes.Buffer)
	// Write status
	buf.WriteByte(packet.Status)
	// Write statement ID
	binary.Write(buf, binary.LittleEndian, packet.StatementID)
	// Write number of columns
	binary.Write(buf, binary.LittleEndian, packet.NumColumns)
	// Write number of parameters
	binary.Write(buf, binary.LittleEndian, packet.NumParams)
	// Write filler byte (0x00)
	buf.WriteByte(0x00)
	// Write warning count
	binary.Write(buf, binary.LittleEndian, packet.WarningCount)
	return buf.Bytes(), nil
}

func encodeMySQLResultSet(resultSet *models.MySQLResultSet) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write column count
	writeLengthEncodedIntegers(buf, uint64(len(resultSet.Columns)))

	// Write columns
	for _, column := range resultSet.Columns {
		writeLengthEncodedStrings(buf, column.Catalog)
		writeLengthEncodedStrings(buf, column.Schema)
		writeLengthEncodedStrings(buf, column.Table)
		writeLengthEncodedStrings(buf, column.OrgTable)
		writeLengthEncodedStrings(buf, column.Name)
		writeLengthEncodedStrings(buf, column.OrgName)
		buf.WriteByte(0x0c) // Length of the fixed-length fields (12 bytes)
		binary.Write(buf, binary.LittleEndian, column.CharacterSet)
		binary.Write(buf, binary.LittleEndian, column.ColumnLength)
		buf.WriteByte(columnTypeValues[column.ColumnType])
		binary.Write(buf, binary.LittleEndian, column.Flags)
		buf.WriteByte(column.Decimals)
		buf.Write([]byte{0x00, 0x00}) // Filler

		if column.DefaultValue != "" {
			writeLengthEncodedStrings(buf, column.DefaultValue)
		}
	}

	// Write EOF packet header
	buf.Write([]byte{0xfe, 0x00, 0x00, 0x02, 0x00})

	// Write rows
	for _, row := range resultSet.Rows {
		for _, value := range row.Columns {
			if strValue, ok := value.(string); ok {
				writeLengthEncodedStrings(buf, strValue)
			}
		}
	}

	// Write EOF packet header again
	buf.Write([]byte{0xfe, 0x00, 0x00, 0x02, 0x00})

	return buf.Bytes(), nil
}

func encodeColumnDefinitionPacket(packet *models.ColumnDefinitionPacket) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write the column attributes
	writeLengthEncodedStrings(buf, packet.Catalog)
	writeLengthEncodedStrings(buf, packet.Schema)
	writeLengthEncodedStrings(buf, packet.Table)
	writeLengthEncodedStrings(buf, packet.OrgTable)
	writeLengthEncodedStrings(buf, packet.Name)
	writeLengthEncodedStrings(buf, packet.OrgName)

	// Write fixed-length fields
	buf.WriteByte(0x0c)
	binary.Write(buf, binary.LittleEndian, packet.CharacterSet)
	binary.Write(buf, binary.LittleEndian, packet.ColumnLength)

	// Write column type
	buf.WriteByte(columnTypeValues[packet.ColumnType])

	// Write flags and decimals
	binary.Write(buf, binary.LittleEndian, packet.Flags)
	buf.WriteByte(byte(packet.Decimals))
	buf.WriteByte(0x00) // Filler

	// Write default value if available
	if packet.DefaultValue != "" {
		writeLengthEncodedStrings(buf, packet.DefaultValue)
	}

	return buf.Bytes(), nil
}

func encodeRow(row *models.Row) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write the number of columns
	writeLengthEncodedIntegers(buf, uint64(len(row.Columns)))

	// Write each column value as a length-encoded string
	for _, colValue := range row.Columns {
		if strValue, ok := colValue.(string); ok {
			writeLengthEncodedStrings(buf, strValue)
		} else {
			return nil, fmt.Errorf("column value is not a string")
		}
	}

	return buf.Bytes(), nil
}

func writeLengthEncodedIntegers(buf *bytes.Buffer, value uint64) {
	if value <= 250 {
		buf.WriteByte(byte(value))
	} else if value <= 0xffff {
		buf.WriteByte(0xfc)
		buf.WriteByte(byte(value))
		buf.WriteByte(byte(value >> 8))
	} else if value <= 0xffffff {
		buf.WriteByte(0xfd)
		buf.WriteByte(byte(value))
		buf.WriteByte(byte(value >> 8))
		buf.WriteByte(byte(value >> 16))
	} else {
		buf.WriteByte(0xfe)
		binary.Write(buf, binary.LittleEndian, value)
	}
}

func writeLengthEncodedStrings(buf *bytes.Buffer, value string) {
	data := []byte(value)
	length := uint64(len(data))
	writeLengthEncodedIntegers(buf, length)
	buf.Write(data)
}

func encodeMySQLOK(packet *models.MySQLOKPacket) ([]byte, error) {
	buf := new(bytes.Buffer)
	// Write header (0x00)
	buf.WriteByte(0x00)
	// Write affected rows
	buf.Write(encodeLengthEncodedInteger(packet.AffectedRows))
	// Write last insert ID
	buf.Write(encodeLengthEncodedInteger(packet.LastInsertID))
	// Write status flags
	binary.Write(buf, binary.BigEndian, packet.StatusFlags)
	// Write warnings
	binary.Write(buf, binary.BigEndian, packet.Warnings)
	// Write info
	buf.WriteString(packet.Info)
	return buf.Bytes(), nil
}

func encodeHandshakeResponseOk(packet *models.MySQLHandshakeResponseOk) ([]byte, error) {
	var buf bytes.Buffer

	var packetIndicator byte
	switch packet.PacketIndicator {
	case "OK":
		packetIndicator = iOK
	case "AuthMoreData":
		packetIndicator = iAuthMoreData
	case "EOF":
		packetIndicator = iEOF
	default:
		return nil, fmt.Errorf("unknown packet indicator")
	}

	buf.WriteByte(packetIndicator)

	if packet.PacketIndicator == "AuthMoreData" {
		var authData byte
		switch packet.PluginDetails.Type {
		case "cachingSha2PasswordFastAuthSuccess":
			authData = cachingSha2PasswordFastAuthSuccess
		case "cachingSha2PasswordPerformFullAuthentication":
			authData = cachingSha2PasswordPerformFullAuthentication
		default:
			return nil, fmt.Errorf("unknown auth type")
		}

		// Write auth data
		buf.WriteByte(authData)
	}

	// Write remaining bytes if available
	if len(packet.RemainingBytes) > 0 {
		buf.Write(packet.RemainingBytes)
	}

	// Create header
	header := make([]byte, 4)
	header[0] = 2 // sequence number
	header[1] = 0
	header[2] = 0
	header[3] = 2
	// Prepend header to the payload
	payload := append(header, buf.Bytes()...)

	return payload, nil
}

func encodeToBinary(packet interface{}, operation string, sequence int) ([]byte, error) {
	var data []byte
	var err error
	var bypassHeader = false
	innerPacket, ok := packet.(*interface{})
	if ok {
		packet = *innerPacket
	}
	switch operation {
	case "MySQLHandshakeV10":
		p, ok := packet.(*models.MySQLHandshakeV10Packet)
		if !ok {
			return nil, fmt.Errorf("invalid packet type for HandshakeV10Packet: expected *HandshakeV10Packet, got %T", packet)
		}
		data, err = encodeHandshakePacket(p)
	case "HANDSHAKE_RESPONSE_OK":
		bypassHeader = true
		p, ok := packet.(*models.MySQLHandshakeResponseOk)
		if !ok {
			return nil, fmt.Errorf("invalid packet type for HandshakeResponse: expected *HandshakeResponse, got %T", packet)
		}
		data, err = encodeHandshakeResponseOk(p)
	case "MySQLOK":
		p, ok := packet.(*models.MySQLOKPacket)
		if !ok {
			return nil, fmt.Errorf("invalid packet type for HandshakeResponse: expected *HandshakeResponse, got %T", packet)
		}
		data, err = encodeMySQLOK(p)
	case "COM_STMT_PREPARE_OK":
		p, ok := packet.(*models.MySQLStmtPrepareOk)
		if !ok {
			return nil, fmt.Errorf("invalid packet type for HandshakeResponse: expected *HandshakeResponse, got %T", packet)
		}
		data, err = encodeMySQLStmtPrepareOk(p)
	case "RESULT_SET_PACKET":
		p, ok := packet.(*models.MySQLResultSet)
		if !ok {
			return nil, fmt.Errorf("invalid packet for result set")
		}
		data, err = encodeMySQLResultSet(p)
	default:
		return nil, errors.New("unknown operation type")
	}

	if err != nil {
		return nil, err
	}
	if !bypassHeader {
		header := make([]byte, 4)
		binary.LittleEndian.PutUint32(header, uint32(len(data)))
		header[3] = byte(sequence)
		fmt.Println(uint32(len(data)))
		return append(header, data...), nil
	} else {
		return data, nil
	}
}

func DecodeMySQLPacket(packet MySQLPacket, logger *zap.Logger, destConn net.Conn) (string, MySQLPacketHeader, interface{}, error) {
	data := packet.Payload
	header := packet.Header

	var packetData interface{}
	var packetType string
	var err error

	switch {
	case data[0] == 0x0e: // COM_PING
		packetType = "COM_PING"
		packetData, err = decodeComPing(data)
		lastCommand = 0x0e
	case data[0] == 0x17: // COM_STMT_EXECUTE
		packetType = "COM_STMT_EXECUTE"
		packetData, err = decodeComStmtExecute(data)
		lastCommand = 0x17
	case data[0] == 0x1c: // COM_STMT_FETCH
		packetType = "COM_STMT_FETCH"
		packetData, err = decodeComStmtFetch(data)
		lastCommand = 0x1c
	case data[0] == 0x16: // COM_STMT_PREPARE
		packetType = "COM_STMT_PREPARE"
		packetData, err = decodeComStmtPrepare(data)
		lastCommand = 0x16
	case data[0] == 0x19: // COM_STMT_CLOSE
		packetType = "COM_STMT_CLOSE"
		packetData, err = decodeComStmtClose(data)
		lastCommand = 0x19
	case data[0] == 0x11: // COM_CHANGE_USER
		packetType = "COM_CHANGE_USER"
		packetData, err = decodeComChangeUser(data)
		lastCommand = 0x11
	case data[0] == 0x04: // Result Set Packet
		packetType = "RESULT_SET_PACKET"
		packetData, err = parseResultSet(data)
		lastCommand = 0x04
	case data[0] == 0x0A: // MySQLHandshakeV10
		packetType = "MySQLHandshakeV10"
		packetData, err = decodeMySQLHandshakeV10(data)
		handshakePacket, _ := packetData.(*HandshakeV10Packet)
		handshakePluginName = handshakePacket.AuthPluginName
		lastCommand = 0x0A
	case data[0] == 0x03: // MySQLQuery
		packetType = "MySQLQuery"
		packetData, err = decodeMySQLQuery(data)
		lastCommand = 0x03
	case data[0] == 0x00: // MySQLOK or COM_STMT_PREPARE_OK
		if lastCommand == 0x16 {
			packetType = "COM_STMT_PREPARE_OK"
			packetData, err = decodeComStmtPrepareOk(data)
		} else {
			packetType = "MySQLOK"
			packetData, err = decodeMySQLOK(data)
		}
		lastCommand = 0x00
	case data[0] == 0xFF: // MySQLErr
		packetType = "MySQLErr"
		packetData, err = decodeMySQLErr(data)
		lastCommand = 0xFF
	case data[0] == 0xFE && len(data) > 1: // Auth Switch Packet
		packetType = "AuthSwitchRequest"
		packetData, err = decodeAuthSwitchRequest(data)
		lastCommand = 0xFE
	case data[0] == 0xFE: // EOF packet
		packetType = "MySQLEOF"
		packetData, err = decodeMYSQLEOF(data)
		lastCommand = 0xFE
	case data[0] == 0x02: // New packet type
		packetType = "NewPacketType2"
		packetData, err = decodePacketType2(data)
		lastCommand = 0x02
	case data[0] == 0x18: // SEND_LONG_DATA Packet
		packetType = "COM_STMT_SEND_LONG_DATA"
		packetData, err = decodeComStmtSendLongData(data)
		lastCommand = 0x18
	case data[0] == 0x1a: // STMT_RESET Packet
		packetType = "COM_STMT_RESET"
		packetData, err = decodeComStmtReset(data)
		lastCommand = 0x1a
	case data[0] == 0x8d: // Handshake Response packet
		packetType = "HANDSHAKE_RESPONSE"
		packetData, err = decodeHandshakeResponse(data)
		lastCommand = 0x8d // This value may differ depending on the handshake response protocol version
	case data[0] == 0x01: // Handshake Response packet
		packetType = "HANDSHAKE_RESPONSE_OK"
		packetData, err = decodeHandshakeResponseOk(data)
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
func decodeAuthSwitchRequest(data []byte) (*AuthSwitchRequest, error) {
	if len(data) < 2 {
		return nil, errors.New("invalid auth switch request packet")
	}

	pluginName, _, err := nullTerminatedString(data[1:])
	if err != nil {
		return nil, err
	}

	authSwitchData := data[len(pluginName)+2:]

	return &AuthSwitchRequest{
		PluginName: pluginName,
		Data:       authSwitchData,
	}, nil
}

func decodeComStmtPrepare(data []byte) (*ComStmtPreparePacket, error) {
	if len(data) < 1 {
		return nil, errors.New("data too short for COM_STMT_PREPARE")
	}
	// data[1:] will skip the command byte and leave the query string
	query := string(data[1:])
	query = strings.ReplaceAll(query, "\t", "")
	return &ComStmtPreparePacket{Query: query}, nil
}

func decodeComStmtClose(data []byte) (*ComStmtClosePacket, error) {
	if len(data) < 5 {
		return nil, errors.New("data too short for COM_STMT_CLOSE")
	}
	// Statement ID is 4-byte, little-endian integer after command byte
	statementID := binary.LittleEndian.Uint32(data[1:])
	return &ComStmtClosePacket{
		StatementID: statementID,
	}, nil
}

func decodeComStmtPrepareOk(data []byte) (*StmtPrepareOk, error) {
	// ensure the packet is long enough
	if len(data) < 12 {
		return nil, errors.New("data length is not enough for COM_STMT_PREPARE_OK")
	}
	// construct the response
	response := &StmtPrepareOk{
		Status:      data[0],
		StatementID: binary.LittleEndian.Uint32(data[1:5]),
		NumColumns:  binary.LittleEndian.Uint16(data[5:7]),
		NumParams:   binary.LittleEndian.Uint16(data[7:9]),
		// skip filler byte at data[9]
		WarningCount: binary.LittleEndian.Uint16(data[10:12]),
	}
	return response, nil
}

func nullTerminatedString(data []byte) (string, int, error) {
	pos := bytes.IndexByte(data, 0)
	if pos == -1 {
		return "", 0, errors.New("null-terminated string not found")
	}
	return string(data[:pos]), pos, nil
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
	AffectedRows uint64 `json:"affected_rows,omitempty" yaml:"affected_rows"`
	LastInsertID uint64 `json:"last_insert_id,omitempty" yaml:"last_insert_id"`
	StatusFlags  uint16 `json:"status_flags,omitempty" yaml:"status_flags"`
	Warnings     uint16 `json:"warnings,omitempty" yaml:"warnings"`
	Info         string `json:"info,omitempty" yaml:"info"`
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

const (
	iOK               = 0x00
	iERR              = 0xff
	iLocalInFile      = 0xfb
	iEOF         byte = 0xfe
	flagUnsigned
	statusMoreResultsExists
)

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
func readUint24(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

func readLengthEncodedIntegers(b []byte) (uint64, int) {
	// Check the first byte
	switch b[0] {
	case 0xfb:
		// 0xfb represents NULL
		return 0, 1
	case 0xfc:
		// 0xfc means the next 2 bytes are the integer
		return uint64(binary.LittleEndian.Uint16(b[1:])), 3
	case 0xfd:
		// 0xfd means the next 3 bytes are the integer
		return uint64(binary.LittleEndian.Uint32(append(b[1:4], 0))), 4
	case 0xfe:
		// 0xfe means the next 8 bytes are the integer
		return binary.LittleEndian.Uint64(b[1:]), 9
	default:
		// If the first byte is less than 0xfb, it is the integer itself
		return uint64(b[0]), 1
	}
}

func readLengthEncodedStrings(b []byte) (string, int) {
	length, n := readLengthEncodedIntegers(b)
	return string(b[n : n+int(length)]), n + int(length)
}

type fieldFlag uint16

const (
	TypeDecimal    byte = 0x00
	TypeTiny       byte = 0x01
	TypeShort      byte = 0x02
	TypeLong       byte = 0x03
	TypeFloat      byte = 0x04
	TypeDouble     byte = 0x05
	TypeNull       byte = 0x06
	TypeTimestamp  byte = 0x07
	TypeLongLong   byte = 0x08
	TypeInt24      byte = 0x09
	TypeDate       byte = 0x0a
	TypeTime       byte = 0x0b
	TypeDateTime   byte = 0x0c
	TypeYear       byte = 0x0d
	TypeNewDate    byte = 0x0e
	TypeVarChar    byte = 0x0f
	TypeBit        byte = 0x10
	TypeNewDecimal byte = 0xf6
	TypeEnum       byte = 0xf7
	TypeSet        byte = 0xf8
	TypeTinyBlob   byte = 0xf9
	TypeMediumBlob byte = 0xfa
	TypeLongBlob   byte = 0xfb
	TypeBlob       byte = 0xfc
	TypeVarString  byte = 0xfd
	TypeString     byte = 0xfe
	TypeGeometry   byte = 0xff
)

func parseTimestamp(b []byte) (time.Time, int) {
	timestamp := binary.LittleEndian.Uint64(b)
	return time.Unix(int64(timestamp), 0), 8 // assuming the timestamp is 8 bytes
}

func ReadLengthEncodedString(b []byte) (string, int) {
	var length int
	var n int

	switch {
	case b[0] < 0xfb:
		length = int(b[0])
		n = 1
	case b[0] == 0xfb:
		length = 0
		n = 1
	case b[0] == 0xfc:
		length = int(binary.LittleEndian.Uint16(b[1:3]))
		n = 3
	case b[0] == 0xfd:
		length = int(readUint24(b[1:4]))
		n = 4
	case b[0] == 0xfe:
		length = int(binary.LittleEndian.Uint64(b[1:9]))
		n = 9
	}

	strValue := string(b[n : n+length])

	return strValue, n + length
}

func parseRow(b []byte, columnDefinitions []*ColumnDefinitionPacket) (*Row, []byte, error) {
	row := &Row{
		Columns: make(map[string]interface{}),
	}

	// Check for EOF marker at the start of b and skip it
	EOFMarker := []byte{0x05, 0x00, 0x00, 0x06, 0xfe, 0x00, 0x00, 0x02, 0x00}
	if len(b) >= 9 && bytes.Equal(b[:9], EOFMarker) {
		b = b[9:]
	} else {
		return nil, nil, nil
	}
	//server status

	skip, err := strconv.Atoi(string(b[0]))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert byte to integer: %v", err)
	}

	// Skip the bytes
	b = b[skip:]

	// Process each column
	for _, column := range columnDefinitions {
		var value interface{}
		var length int

		switch column.ColumnType {
		case "fieldTypeTimestamp":
			if len(b) < 8 {
				return nil, nil, fmt.Errorf("byte slice too short for timestamps")
			}
			unixTime := binary.BigEndian.Uint64(b[:8])
			value = time.Unix(0, int64(unixTime)).Format(time.RFC3339)
			length = 8
		case "fieldTypeInt24", "fieldTypeLong":
			value = int32(binary.LittleEndian.Uint32(b[:4]))
			length = 4
		case "fieldTypeLongLong":
			value = int64(binary.LittleEndian.Uint64(b[:8]))
			length = 8
		case "fieldTypeFloat":
			value = math.Float32frombits(binary.LittleEndian.Uint32(b[:4]))
			length = 4
		case "fieldTypeDouble":
			value = math.Float64frombits(binary.LittleEndian.Uint64(b[:8]))
			length = 8
		default:
			// Find the next special byte (either 0x0b or 0x17)
			idx := bytes.IndexAny(b, "\x0b\x17\xe17")
			if idx == -1 {
				return nil, nil, fmt.Errorf("expected byte not found")
			}

			// Find the first non-null character
			start := bytes.IndexFunc(b[:idx], func(r rune) bool {
				return r != '\x00'
			})
			if start == -1 {
				return nil, nil, fmt.Errorf("non-null character not found")
			}

			// Extract the string, remove non-printable characters
			str := string(b[start:idx])
			re := regexp.MustCompile(`[^[:print:]\t\r\n]`)
			cleanedStr := re.ReplaceAllString(str, "")
			value = cleanedStr
			length = idx + 1
		}

		row.Columns[column.Name] = value
		b = b[length:]
	}

	return row, b, nil
}

func parseResultSet(b []byte) (interface{}, error) {
	allColumns := make([]*ColumnDefinitionPacket, 0)
	allRows := make([]*Row, 0)

	var err error

	for len(b) > 4 {
		// The first packet is the column count packet
		columnCount, n := readLengthEncodedIntegers(b)
		b = b[n:]
		// Parse the column
		columns := make([]*ColumnDefinitionPacket, 0)
		for i := uint64(0); i < columnCount; i++ {
			var columnPacket *ColumnDefinitionPacket
			columnPacket, b, err = parseColumnDefinitionPacket(b)
			if err != nil {
				return nil, err
			}
			columns = append(columns, columnPacket)
		}
		allColumns = append(allColumns, columns...)

		// Parse the rows
		for len(b) > 4 && !bytes.Equal(b[:4], []byte{0xfe, 0x00, 0x00, 0x02, 0x00}) {
			var row *Row
			row, b, err = parseRow(b, columns)
			if err != nil {
				return nil, err
			}
			allRows = append(allRows, row)
		}
	}
	resultSet := &ResultSet{
		Columns: allColumns,
		Rows:    allRows,
	}

	return resultSet, err
}

func parseColumnDefinitionPacket(b []byte) (*ColumnDefinitionPacket, []byte, error) {
	packet := &ColumnDefinitionPacket{}
	var n int
	var m int

	// Skip the first 4 bytes (packet header)
	b = b[4:]

	packet.Catalog, n = readLengthEncodedStrings(b)
	b = b[n:]
	packet.Schema, n = readLengthEncodedStrings(b)
	b = b[n:]
	packet.Table, n = readLengthEncodedStrings(b)
	b = b[n:]
	packet.OrgTable, n = readLengthEncodedStrings(b)
	b = b[n:]
	packet.Name, n = readLengthEncodedStrings(b)
	b = b[n:]
	packet.OrgName, n = readLengthEncodedStrings(b)
	b = b[n:]
	b = b[1:] // Skip the next byte (length of the fixed-length fields)
	packet.CharacterSet = binary.LittleEndian.Uint16(b)
	b = b[2:]
	packet.ColumnLength = binary.LittleEndian.Uint32(b)
	b = b[4:]
	if name, ok := mySQLfieldTypeNames[b[0]]; ok {
		packet.ColumnType = name
	} else {
		packet.ColumnType = "unknown"
	}
	b = b[1:]

	packet.Flags = binary.LittleEndian.Uint16(b)
	b = b[2:]
	packet.Decimals = uint8(b[0])
	b = b[2:] // Skip filler
	if len(b) > 0 {
		packet.DefaultValue, m = readLengthEncodedStrings(b)
		b = b[m:]
	}

	return packet, b, nil
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

func decodeLengthEncodedInt(data []byte) (int, int) {
	if data[0] < 251 {
		return int(data[0]), 1
	} else if data[0] == 252 {
		return int(binary.LittleEndian.Uint16(data[1:3])), 3
	} else if data[0] == 253 {
		return int(data[1]) | int(data[2])<<8 | int(data[3])<<16, 4
	} else {
		return int(binary.LittleEndian.Uint64(data[1:9])), 9
	}
}

func decodeHandshakeResponse(data []byte) (*HandshakeResponse, error) {
	if len(data) < 32 {
		return nil, errors.New("handshake response packet too short")
	}

	packet := &HandshakeResponse{}

	packet.CapabilityFlags = binary.LittleEndian.Uint32(data[:4])
	data = data[4:]

	packet.MaxPacketSize = binary.LittleEndian.Uint32(data[:4])
	data = data[4:]

	packet.CharacterSet = data[0]
	data = data[1:]

	copy(packet.Reserved[:], data[:23])
	data = data[23:]

	idx := bytes.IndexByte(data, 0x00)
	if idx == -1 {
		return nil, errors.New("malformed handshake response packet: missing null terminator for Username")
	}
	packet.Username = string(data[:idx])
	data = data[idx+1:]

	authDataLen := int(data[0])
	data = data[1:]

	if len(data) < authDataLen {
		return nil, errors.New("handshake response packet too short for auth data")
	}
	packet.AuthData = data[:authDataLen]
	data = data[authDataLen:]

	idx = bytes.IndexByte(data, 0x00)
	if idx != -1 {
		packet.Database = string(data[:idx])
		data = data[idx+1:]
	}

	if packet.CapabilityFlags&0x00080000 != 0 {
		idx := bytes.IndexByte(data, 0x00)
		if idx == -1 {
			return nil, errors.New("malformed handshake response packet: missing null terminator for AuthPluginName")
		}
		packet.AuthPluginName = string(data[:idx])
	}

	return packet, nil
}

func decodeHandshakeResponseOk(data []byte) (*HandshakeResponseOk, error) {
	var (
		packetIndicator string
		authType        string
		message         string
		remainingBytes  []byte
	)

	switch data[0] {
	case iOK:
		packetIndicator = "OK"
	case iAuthMoreData:
		packetIndicator = "AuthMoreData"
	case iEOF:
		packetIndicator = "EOF"
	default:
		packetIndicator = "Unknown"
	}

	if data[0] == iAuthMoreData {
		count := int(data[0])
		var authData = data[1 : count+1]
		switch handshakePluginName {
		case "caching_sha2_password":
			switch len(authData) {
			case 1:
				switch authData[0] {
				case cachingSha2PasswordFastAuthSuccess:
					authType = "cachingSha2PasswordFastAuthSuccess"
					message = "Ok"
					remainingBytes = data[count+1:]
				case cachingSha2PasswordPerformFullAuthentication:
					authType = "cachingSha2PasswordPerformFullAuthentication"
					message = ""
					remainingBytes = data[count+1:]
				}
			}
		}
	}

	return &HandshakeResponseOk{
		PacketIndicator: packetIndicator,
		PluginDetails: PluginDetails{
			Type:    authType,
			Message: message,
		},
		RemainingBytes: remainingBytes,
	}, nil
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

	data = data[1:] // Filler

	if len(data) < 4 {
		return nil, fmt.Errorf("handshake packet too short")
	}
	packet.CapabilityFlags = binary.LittleEndian.Uint32(data)
	data = data[4:]

	packet.CharacterSet = data[0]
	data = data[1:]

	packet.StatusFlags = binary.LittleEndian.Uint16(data)
	data = data[2:]

	if packet.CapabilityFlags&0x800000 != 0 {
		authPluginDataLen := int(data[0])
		if authPluginDataLen > 8 {
			data = data[1:]
			packet.AuthPluginData = append(packet.AuthPluginData, data[:authPluginDataLen-8]...)
			data = data[authPluginDataLen-8:]
		} else {
			data = data[1:]
		}
	}

	data = data[10:] // Reserved 10 bytes

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

// No response is sent back to client in this packet
func decodeComStmtSendLongData(packet []byte) (COM_STMT_SEND_LONG_DATA, error) {
	if len(packet) < 7 || packet[0] != 0x18 {
		return COM_STMT_SEND_LONG_DATA{}, fmt.Errorf("invalid COM_STMT_SEND_LONG_DATA packet")
	}
	stmtID := binary.LittleEndian.Uint32(packet[1:5])
	paramID := binary.LittleEndian.Uint16(packet[5:7])
	data := packet[7:]
	return COM_STMT_SEND_LONG_DATA{
		StatementID: stmtID,
		ParameterID: paramID,
		Data:        data,
	}, nil
}

func decodeComStmtReset(packet []byte) (stmtID uint32, err error) {
	if len(packet) != 5 || packet[0] != 0x1a {
		return 0, fmt.Errorf("invalid COM_STMT_RESET packet")
	}
	stmtID = binary.LittleEndian.Uint32(packet[1:5])
	return stmtID, nil
}

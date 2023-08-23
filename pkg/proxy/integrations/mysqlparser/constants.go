package mysqlparser

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

const (
	iAuthMoreData                                byte = 0x01
	cachingSha2PasswordRequestPublicKey               = 2
	cachingSha2PasswordFastAuthSuccess                = 3
	cachingSha2PasswordPerformFullAuthentication      = 4
)

const (
	MaxPacketSize = 1<<24 - 1
)

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
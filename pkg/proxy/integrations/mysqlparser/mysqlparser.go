package mysqlparser

import (
	"net"

	"go.keploy.io/server/pkg/models"
	"go.keploy.io/server/pkg/models/spec"
	"go.keploy.io/server/pkg/proxy/util"
	"go.uber.org/zap"
)

func IsOutgoingMySQL(buffer []byte) bool {
	if len(buffer) < 5 {
		return false
	}
	packetLength := uint32(buffer[0]) | uint32(buffer[1])<<8 | uint32(buffer[2])<<16
	return int(packetLength) == len(buffer)-4
}

func CaptureMySQLMessage(requestBuffer []byte, clientConn, destConn net.Conn, logger *zap.Logger) []*models.Mock {
	_, err := destConn.Write(requestBuffer)
	if err != nil {
		logger.Error("failed to write the request buffer to mysql server", zap.Error(err), zap.String("mysql server address", destConn.RemoteAddr().String()))
		return nil
	}

	responseBuffer, err := util.ReadBytes(destConn)
	if err != nil {
		logger.Error("failed to read reply from the mysql server", zap.Error(err), zap.String("mysql server address", destConn.RemoteAddr().String()))
		return nil
	}

	_, err = clientConn.Write(responseBuffer)
	if err != nil {
		logger.Error("failed to write the reply message to mysql client", zap.Error(err))
		return nil
	}

	deps := []*models.Mock{}

	opr, requestHeader, mysqlRequest, err := DecodeMySQLPacket(requestBuffer)
	if err != nil {
		logger.Error("failed to decode the mysql packet from the client", zap.Error(err))
		return nil
	}

	opr, responseHeader, mysqlResp, err := DecodeMySQLPacket(responseBuffer)
	if err != nil {
		logger.Error("failed to decode the mysql packet from the destination server", zap.Error(err))
		return nil
	}

	meta := map[string]string{
		"operation": opr,
	}
	mysqlMock := &models.Mock{
		Version: models.V1Beta2,
		Kind:    models.MySQL,
		Name:    "",
	}
	mysqlSpec := &spec.MySQLSpec{
		Metadata: meta,
		RequestHeader: spec.MySQLPacketHeader{
			PacketLength: requestHeader.PayloadLength,
			PacketNumber: requestHeader.SequenceID,
		},
		ResponseHeader: spec.MySQLPacketHeader{
			PacketLength: responseHeader.PayloadLength,
			PacketNumber: responseHeader.SequenceID,
		},
	}
	err = mysqlSpec.Request.Encode(mysqlRequest)
	if err != nil {
		logger.Error("failed to encode the request mysql packet into yaml doc", zap.Error(err))
		return nil
	}
	err = mysqlSpec.Response.Encode(mysqlResp)
	if err != nil {
		logger.Error("failed to encode the response mysql packet into yaml doc", zap.Error(err))
		return nil
	}
	mysqlMock.Spec.Encode(mysqlSpec)
	deps = append(deps, mysqlMock)

	return deps
}

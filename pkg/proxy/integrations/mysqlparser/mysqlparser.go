package mysqlparser

import (
	"fmt"
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

	// After sending the handshake response
	responseBuffer, err := util.ReadBytes(destConn)
	if err != nil {
		logger.Error("failed to read reply from the mysql server", zap.Error(err), zap.String("mysql server address", destConn.RemoteAddr().String()))
		return nil
	}

	fmt.Println("This is the response buffer:", string(responseBuffer), responseBuffer)
	_, err = clientConn.Write(responseBuffer)

	opr, _, packet, err := DecodeMySQLPacket(responseBuffer)
	if err != nil {
		logger.Error("failed to decode the mysql packet from the server", zap.Error(err))
		return nil
	}

	if opr == "MySQLOK" {
		okPacket := packet.(*OKPacket)
		logger.Info("Received OKPacket", zap.Any("okPacket", okPacket))

	} else if opr == "MySQLErr" {
		errPacket := packet.(*ERRPacket)
		logger.Error("Received ERRPacket", zap.Any("errPacket", errPacket))
		return nil

	} else {
		logger.Error("Unexpected packet from server", zap.String("operation", opr))
		return nil
	}

	deps := []*models.Mock{}

	opr, requestHeader, mysqlRequest, err := DecodeMySQLPacket(requestBuffer)
	if err != nil {
		logger.Error("failed to decode the mysql packet from the client", zap.Error(err))
		// return nil
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
		Kind:    models.SQL,
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

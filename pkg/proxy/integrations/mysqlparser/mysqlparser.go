package mysqlparser

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

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

func ReadFirstBuffer(clientConn, destConn net.Conn) ([]byte, string, error) {

	// Attempt to read from destConn first
	n, err := util.ReadBytes(destConn)

	// If there is data from destConn, return it
	if err == nil {
		return n, "destination", nil
	}

	// If the error is a timeout, try to read from clientConn
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		n, err = util.ReadBytes(clientConn)

		// If there is data from clientConn, return it
		if err == nil {
			return n, "client", nil
		}

		// Return any error from reading clientConn
		return nil, "", err
	}

	// Return any other error from reading destConn
	return nil, "", err
}

func readLengthEncodedString(data []byte) (result string, isNull bool, n int) {
	// Check first byte
	switch data[0] {
	case 0xfb: // MySQL NULL value
		return "", true, 1
	case 0xfc: // Encoded in the next 2 bytes
		length := int(binary.LittleEndian.Uint16(data[1:3]))
		return string(data[3 : 3+length]), false, 3 + length
	case 0xfd: // Encoded in the next 3 bytes
		length := int(binary.LittleEndian.Uint32(append(data[1:4], 0)))
		return string(data[4 : 4+length]), false, 4 + length
	case 0xfe: // Encoded in the next 8 bytes
		length := int(binary.LittleEndian.Uint64(data[1:9]))
		return string(data[9 : 9+length]), false, 9 + length
	default: // Encoded in the first byte
		length := int(data[0])
		return string(data[1 : 1+length]), false, 1 + length
	}
}

func handleClientQueries(initialBuffer []byte, clientConn, destConn net.Conn, logger *zap.Logger) ([]*models.Mock, error) {
	deps := []*models.Mock{}
	firstIteration := true

	for {
		var queryBuffer []byte
		var err error

		if firstIteration && initialBuffer != nil {
			queryBuffer = initialBuffer
			firstIteration = false
		} else {
			queryBuffer, err = util.ReadBytes(clientConn)
			if err != nil {
				logger.Error("failed to read query from the mysql client", zap.Error(err))
				return nil, err
			}
		}
		opr, requestHeader, mysqlRequest, err := DecodeMySQLPacket(bytesToMySQLPacket(queryBuffer), logger, destConn)
		// Break the loop when the client stops sending data
		if len(queryBuffer) == 0 || opr == "COM_STMT_CLOSE" {
			break
		}

		//fmt.Println("the query for mysql: ", queryBuffer)

		res, err := destConn.Write(queryBuffer)
		if err != nil {
			logger.Error("failed to write query to mysql server", zap.Error(err))
			return nil, err
		}
		if res == 9 {
			break
		}
		// Reading the query response
		queryResponse, err := util.ReadBytes(destConn)
		if err != nil {
			logger.Error("failed to read query response from mysql server", zap.Error(err))
			return nil, err
		}

		// Sending the query response back to the client
		_, err = clientConn.Write(queryResponse)
		if err != nil {
			logger.Error("failed to write query response to mysql client", zap.Error(err))
			return nil, err
		}

		opr, requestHeader, mysqlRequest, err = DecodeMySQLPacket(bytesToMySQLPacket(queryBuffer), logger, destConn)
		if err != nil {
			logger.Error("Failed to decode the MySQL packet from the client", zap.Error(err))
			continue
		}

		opr1, responseHeader, mysqlResp, err := DecodeMySQLPacket(bytesToMySQLPacket(queryResponse), logger, destConn)
		if err != nil {
			logger.Error("Failed to decode the MySQL packet from the destination server", zap.Error(err))
			continue
		}
		fmt.Print("the request ", mysqlRequest)
		fmt.Print("the response ", mysqlResp)

		meta := map[string]string{
			"operation":         opr,
			"responseOperation": opr1,
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
		err = mysqlSpec.Request.Encode(&mysqlRequest)
		if err != nil {
			logger.Error("Failed to encode the request MySQL packet into YAML doc", zap.Error(err))
			continue
		}
		err = mysqlSpec.Response.Encode(mysqlResp)
		if err != nil {
			logger.Error("Failed to encode the response MySQL packet into YAML doc", zap.Error(err))
			continue
		}
		mysqlMock.Spec.Encode(mysqlSpec)
		deps = append(deps, mysqlMock)
	}
	return deps, nil
}
func bytesToMySQLPacket(buffer []byte) MySQLPacket {
	// Assuming buffer is long enough
	length := binary.LittleEndian.Uint32(append(buffer[0:3], 0))
	sequenceID := buffer[3]
	payload := buffer[4:]

	return MySQLPacket{
		Header: MySQLPacketHeader{
			PayloadLength: length,
			SequenceID:    sequenceID,
		},
		Payload: payload,
	}
}

func CaptureMySQLMessage(requestBuffer []byte, clientConn, destConn net.Conn, logger *zap.Logger) []*models.Mock {
	var deps []*models.Mock

	data, source, err := ReadFirstBuffer(clientConn, destConn)
	if err != nil {
		logger.Error("failed to read initial data", zap.Error(err))
		return nil
	}

	if source == "destination" {

		// After sending the handshake response
		handshakeResponseBuffer := data

		_, err = clientConn.Write(handshakeResponseBuffer)

		if err != nil {
			logger.Error("failed to write handshake request to client", zap.Error(err))
			return nil
		}
		handshakeResponseFromClient, err := util.ReadBytes(clientConn)
		if err != nil {
			logger.Error("failed to read handshake respnse from client", zap.Error(err))
			return nil
		}

		_, err = destConn.Write(handshakeResponseFromClient)
		if err != nil {
			logger.Error("failed to write handshake respnse to server", zap.Error(err))
			return nil
		}
		//fmt.Println("number of bytes writen to server Conn", n)
		time.Sleep(100 * time.Millisecond)

		okPacket1, err := util.ReadBytes(destConn)
		if err != nil {
			logger.Error("failed to read packet from server after handshake", zap.Error(err))
			return nil
		}
		//fmt.Println("the packet from mysql server after handshake", (okPacket1))
		_, err = clientConn.Write(okPacket1)

		if err != nil {
			logger.Error("failed to write the packet to mysql client", zap.Error(err))
			return nil
		}
		//handshake complete

		// After completing the handshake process, handle the client queries
		deps, err = handleClientQueries(nil, clientConn, destConn, logger)
		if err != nil {
			logger.Error("failed to handle client queries", zap.Error(err))
			return nil
		}
	} else if source == "client" {
		// queryBuffer := data
		deps, err = handleClientQueries(data, clientConn, destConn, logger)
		if err != nil {
			logger.Error("failed to handle client queries", zap.Error(err))
			return nil
		}
	}

	return deps
}

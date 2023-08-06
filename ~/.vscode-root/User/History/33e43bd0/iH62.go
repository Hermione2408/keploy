package mysqlparser

import (
	"encoding/binary"
	"net"
	"time"

	"go.keploy.io/server/pkg/hooks"
	"go.keploy.io/server/pkg/models"
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

func ProcessOutgoingMySql(clientConnId, destConnId int, requestBuffer []byte, clientConn, destConn net.Conn, h *hooks.Hook, started time.Time, readRequestDelay time.Duration, logger *zap.Logger) {
	// fmt.Println("into processing mongo. clientConnId: ", clientConnId)
	switch models.GetMode() {
	case models.MODE_RECORD:
		// capturedDeps := encodeOutgoingMongo(requestBuffer, clientConn, destConn, logger)
		encodeOutgoingMySql(clientConnId, destConnId, requestBuffer, clientConn, destConn, h, started, readRequestDelay, logger)

		// *deps = append(*deps, capturedDeps...)
		// for _, v := range capturedDeps {
		// 	h.AppendDeps(v)
		// 	// h.WriteMock(v)
		// }
	case models.MODE_TEST:
		// fmt.Println("into test mode. clientConnId: ", clientConnId)
	//	decodeOutgoingMySql(clientConnId, destConnId, requestBuffer, clientConn, destConn, h, started, readRequestDelay, logger)
	default:
	}
}

func encodeOutgoingMySql(clientConnId, destConnId int, requestBuffer []byte, clientConn, destConn net.Conn, h *hooks.Hook, started time.Time, readRequestDelay time.Duration, logger *zap.Logger) {
	// var deps []*models.Mock

	data, source, err := ReadFirstBuffer(clientConn, destConn)
	if err != nil {
		logger.Error("failed to read initial data", zap.Error(err))
		return
	}

	if source == "destination" {

		// After sending the handshake response
		handshakeResponseBuffer := data

		_, err = clientConn.Write(handshakeResponseBuffer)

		if err != nil {
			logger.Error("failed to write handshake request to client", zap.Error(err))
			return
		}
		handshakeResponseFromClient, err := util.ReadBytes(clientConn)
		if err != nil {
			logger.Error("failed to read handshake respnse from client", zap.Error(err))
			return
		}

		_, err = destConn.Write(handshakeResponseFromClient)
		if err != nil {
			logger.Error("failed to write handshake respnse to server", zap.Error(err))
			return
		}
		//fmt.Println("number of bytes writen to server Conn", n)
		// time.Sleep(1000 * time.Millisecond)

		okPacket1, err := util.ReadBytes(destConn)
		if err != nil {
			logger.Error("failed to read packet from server after handshake", zap.Error(err))
			return
		}
		//fmt.Println("the packet from mysql server after handshake", (okPacket1))
		_, err = clientConn.Write(okPacket1)

		if err != nil {
			logger.Error("failed to write the packet to mysql client", zap.Error(err))
			return
		}
		// okpacket2, err := util.ReadBytes(clientConn)
		// if err != nil {
		// 	logger.Error("failed to read handshake respnse from client", zap.Error(err))
		// 	return
		// }

		// _, err = destConn.Write(okpacket2)
		// if err != nil {
		// 	logger.Error("failed to write handshake respnse to server", zap.Error(err))
		// 	return
		// }
		// okPacket3, err := util.ReadBytes(destConn)
		// if err != nil {
		// 	logger.Error("failed to read packet from server after handshake", zap.Error(err))
		// 	return
		// }
		// // Write the server's public key to the client
		// _, err = clientConn.Write(okPacket3)
		// if err != nil {
		// 	logger.Error("failed to write the packet to mysql client", zap.Error(err))
		// 	return
		// }
		// // Read the client's encrypted password
		// encryptedPassword, err := util.ReadBytes(clientConn)
		// if err != nil {
		// 	logger.Error("failed to read handshake response from client", zap.Error(err))
		// 	return
		// }
		// // Forward the client's encrypted password to the server
		// _, err = destConn.Write(encryptedPassword)
		// if err != nil {
		// 	logger.Error("failed to write handshake response to server", zap.Error(err))
		// 	return
		// }
		// // Now the server will respond with an OK packet if the authentication is successful
		// okPacket4, err := util.ReadBytes(destConn)
		// if err != nil {
		// 	logger.Error("failed to read packet from server after handshake", zap.Error(err))
		// 	return
		// }
		// // Write the server's OK packet to the client
		// _, err = clientConn.Write(okPacket4)
		// if err != nil {
		// 	logger.Error("failed to write the packet to mysql client", zap.Error(err))
		// 	return
		// }

		//handshake complete

		// After completing the handshake process, handle the client queries
		_, err = handleClientQueries(h, nil, clientConn, destConn, logger)
		if err != nil {
			logger.Error("failed to handle client queries", zap.Error(err))
			return
		}
	} else if source == "client" {
		// queryBuffer := data
		_, err = handleClientQueries(h, data, clientConn, destConn, logger)
		if err != nil {
			logger.Error("failed to handle client queries", zap.Error(err))
			return
		}
	}

	return
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
func handleClientQueries(h *hooks.Hook, initialBuffer []byte, clientConn, destConn net.Conn, logger *zap.Logger) ([]*models.Mock, error) {
	var (
		mysqlRequests  = []models.MySQLRequest{}
		mysqlResponses = []models.MySQLResponse{}
	)
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
		operation, requestHeader, mysqlRequest, err := DecodeMySQLPacket(bytesToMySQLPacket(queryBuffer), logger, destConn)
		if len(queryBuffer) == 0 || operation == "COM_STMT_CLOSE" {
			break
		}

		mysqlRequests = append(mysqlRequests, models.MySQLRequest{
			Header: &models.MySQLPacketHeader{
				PacketLength: requestHeader.PayloadLength,
				PacketNumber: requestHeader.SequenceID,
			},
			Message: mysqlRequest,
		})

		res, err := destConn.Write(queryBuffer)
		if err != nil {
			logger.Error("failed to write query to mysql server", zap.Error(err))
			return nil, err
		}
		if res == 9 {
			break
		}

		queryResponse, err := util.ReadBytes(destConn)
		if err != nil {
			logger.Error("failed to read query response from mysql server", zap.Error(err))
			return nil, err
		}

		_, err = clientConn.Write(queryResponse)
		if err != nil {
			logger.Error("failed to write query response to mysql client", zap.Error(err))
			return nil, err
		}

		responseOperation, responseHeader, mysqlResp, err := DecodeMySQLPacket(bytesToMySQLPacket(queryResponse), logger, destConn)
		if err != nil {
			logger.Error("Failed to decode the MySQL packet from the destination server", zap.Error(err))
			continue
		}
		mysqlResponses = append(mysqlResponses, models.MySQLResponse{
			Header: &models.MySQLPacketHeader{
				PacketLength: responseHeader.PayloadLength,
				PacketNumber: responseHeader.SequenceID,
			},
			Message: mysqlResp,
		})
	}
	go recordMySQLMessage(h, mysqlRequests, mysqlResponses, operation, responseOperation)
	return nil, nil
}

func recordMySQLMessage(h *hooks.Hook, mysqlRequests []models.MySQLRequest, mysqlResponses []models.MySQLResponse, operation string, responseOperation string) {
	shouldRecordCalls := true
	name := "mocks"

	if shouldRecordCalls {
		meta := map[string]string{
			"operation":         operation,
			"responseOperation": responseOperation,
		}
		mysqlMock := &models.Mock{
			Version: models.V1Beta2,
			Kind:    models.SQL,
			Name:    name,
			Spec: models.MockSpec{
				Metadata:       meta,
				MySqlRequests:  mysqlRequests,
				MySqlResponses: mysqlResponses,
				Created:        time.Now().Unix(),
			},
		}
		h.AppendMocks(mysqlMock)
	}
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

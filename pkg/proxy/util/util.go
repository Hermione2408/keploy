package util

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"time"
)

const maxPacketSize = 1<<24 - 1

// ToIPAddressStr converts the integer IP4 Address to the octet format
func ToIPAddressStr(ip uint32) string {
	// convert the IP address to a 32-bit binary number
	ipBinary := fmt.Sprintf("%032b", ip)
	// fmt.Printf("This is the value of the ipBinary:%v and this is the value of the ip:%v", ipBinary, ip)

	// divide the binary number into four 8-bit segments
	firstByte, _ := strconv.ParseUint(ipBinary[0:8], 2, 64)
	secondByte, _ := strconv.ParseUint(ipBinary[8:16], 2, 64)
	thirdByte, _ := strconv.ParseUint(ipBinary[16:24], 2, 64)
	fourthByte, _ := strconv.ParseUint(ipBinary[24:32], 2, 64)

	// concatenate the four decimal segments with a dot separator to form the dot-decimal string
	return fmt.Sprintf("%d.%d.%d.%d", fourthByte, thirdByte, secondByte, firstByte)
}

// ReadBytes function is utilized to read the complete message from the reader until the end of the file (EOF).
// It returns the content as a byte array.
func ReadBytes(reader io.Reader) ([]byte, error) {
	var buffer []byte

	for {
		// Create a temporary buffer to hold the incoming bytes
		buf := make([]byte, 1024)
		rand.Seed(time.Now().UnixNano())

		// Read bytes from the Reader
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		// Append the bytes to the buffer
		buffer = append(buffer, buf[:n]...)

		// If we've reached the end of the input stream, break out of the loop
		if err == io.EOF || n != 1024 {
			break
		}
	}

	return buffer, nil
}

var ErrInvalidConn = errors.New("invalid connection")

func ReadPacket(destConn net.Conn) ([]byte, error) {
	var prevData []byte
	reader := bufio.NewReader(destConn)

	for {
		// read packet header
		header := make([]byte, 4)
		_, err := io.ReadFull(reader, header)
		if err != nil {
			// destConn.Close()
			return nil, ErrInvalidConn
		}

		// packet length [24 bit]
		pktLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)

		// packets with length 0 terminate a previous packet which is a
		// multiple of (2^24)-1 bytes long
		if pktLen == 0 {
			// there was no previous packet
			if prevData == nil {
				// destConn.Close()
				return nil, ErrInvalidConn
			}

			return prevData, nil
		}

		// read packet body [pktLen bytes]
		data := make([]byte, pktLen)
		_, err = io.ReadFull(reader, data)
		if err != nil {
			// destConn.Close()
			return nil, ErrInvalidConn
		}

		// Combine the header and the body into a full packet
		fullPacket := append(header, data...)

		// return fullPacket if this was the last packet
		if pktLen < maxPacketSize {
			// zero allocations for non-split packets
			if prevData == nil {
				return fullPacket, nil
			}

			return append(prevData, fullPacket...), nil
		}

		prevData = append(prevData, fullPacket...)
	}
}

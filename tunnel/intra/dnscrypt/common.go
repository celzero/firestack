package dnscrypt

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
)

type CryptoConstruction uint16

const (
	UndefinedConstruction CryptoConstruction = iota
	XSalsa20Poly1305
	XChacha20Poly1305
)

const (
	ClientMagicLen = 8
)

const (
	MaxHTTPBodyLength = 4000000
)

var (
	CertMagic               = [4]byte{0x44, 0x4e, 0x53, 0x43}
	ServerMagic             = [8]byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
	MinDNSPacketSize        = 12 + 5
	MaxDNSPacketSize        = 4096
	MaxDNSUDPPacketSize     = 4096
	MaxDNSUDPSafePacketSize = 1252
	InitialMinQuestionSize  = 512
)

var (
	FileDescriptors   = make([]*os.File, 0)
	FileDescriptorNum = uintptr(0)
)

const (
	InheritedDescriptorsBase = uintptr(50)
)

func PrefixWithSize(packet []byte) ([]byte, error) {
	packetLen := len(packet)
	if packetLen > 0xffff {
		return packet, errors.New("Packet too large")
	}
	packet = append(append(packet, 0), 0)
	copy(packet[2:], packet[:len(packet)-2])
	binary.BigEndian.PutUint16(packet[0:2], uint16(len(packet)-2))
	return packet, nil
}

// TODO: merge this with doh.Accept
func ReadPrefixed(conn *net.Conn) ([]byte, error) {
	buf := make([]byte, 2+MaxDNSPacketSize)
	packetLength, pos := -1, 0
	for {
		readnb, err := (*conn).Read(buf[pos:])
		if err != nil {
			return buf, err
		}
		pos += readnb
		if pos >= 2 && packetLength < 0 {
			packetLength = int(binary.BigEndian.Uint16(buf[0:2]))
			if packetLength > MaxDNSPacketSize-1 {
				return buf, errors.New("dns crypt resp packet too large")
			}
			if packetLength < MinDNSPacketSize {
				return buf, errors.New("dns crypt resp packet too short")
			}
		}
		if packetLength >= 0 && pos >= 2+packetLength {
			return buf[2 : 2+packetLength], nil
		}
	}
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func StringReverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

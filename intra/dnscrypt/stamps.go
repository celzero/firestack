package dnscrypt

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/celzero/firestack/intra/log"
	"github.com/jedisct1/go-dnsstamps"
)

const DefaultPort = 443

type ServerInformalProperties dnsstamps.ServerInformalProperties

const (
	ServerInformalPropertyDNSSEC   = ServerInformalProperties(1) << 0
	ServerInformalPropertyNoLog    = ServerInformalProperties(1) << 1
	ServerInformalPropertyNoFilter = ServerInformalProperties(1) << 2
)

type StampProtoType dnsstamps.StampProtoType

const (
	StampProtoTypePlain         = StampProtoType(0x00)
	StampProtoTypeDNSCrypt      = StampProtoType(0x01)
	StampProtoTypeDoH           = StampProtoType(0x02)
	StampProtoTypeTLS           = StampProtoType(0x03)
	StampProtoTypeDNSCryptRelay = StampProtoType(0x81)
)

func (stampProtoType *StampProtoType) String() string {
	switch *stampProtoType {
	case StampProtoTypePlain:
		return "Plain"
	case StampProtoTypeDNSCrypt:
		return "DNSCrypt"
	case StampProtoTypeDoH:
		return "DoH"
	case StampProtoTypeDNSCryptRelay:
		return "Anonymized DNSCrypt"
	default:
		panic("Unexpected protocol")
	}
}

type ServerStamp = dnsstamps.ServerStamp

func NewDNSCryptServerStampFromLegacy(serverAddrStr string, serverPkStr string, providerName string, props ServerInformalProperties) (ServerStamp, error) {
	if net.ParseIP(serverAddrStr) != nil {
		serverAddrStr = fmt.Sprintf("%s:%d", serverAddrStr, DefaultPort)
	}
	serverPk, err := hex.DecodeString(strings.Replace(serverPkStr, ":", "", -1))
	if err != nil || len(serverPk) != 32 {
		return ServerStamp{}, fmt.Errorf("Unsupported public key: [%s]", serverPkStr)
	}
	return ServerStamp{
		ServerAddrStr: serverAddrStr,
		ServerPk:      serverPk,
		ProviderName:  providerName,
		Props:         dnsstamps.ServerInformalProperties(props),
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}, nil
}

func NewServerStampFromString(stampStr string) (ServerStamp, error) {
	if !strings.HasPrefix(stampStr, "sdns:") {
		return ServerStamp{}, errors.New("Stamps are expected to start with \"sdns:\"")
	}
	stampStr = stampStr[5:]
	stampStr = strings.TrimPrefix(stampStr, "//")
	bin, err := base64.RawURLEncoding.Strict().DecodeString(stampStr)
	if err != nil {
		return ServerStamp{}, err
	}
	if len(bin) < 1 {
		return ServerStamp{}, errors.New("Stamp is too short")
	}
	if bin[0] == uint8(StampProtoTypeDNSCrypt) {
		return newDNSCryptServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDoH) {
		return newDoHServerStamp(bin)
	} else if bin[0] == uint8(StampProtoTypeDNSCryptRelay) {
		return newDNSCryptRelayStamp(bin)
	}
	return ServerStamp{}, errors.New("Unsupported stamp version or protocol")
}

// id(u8)=0x01 props addrLen(1) serverAddr pkStrlen(1) pkStr providerNameLen(1) providerName

func newDNSCryptServerStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: dnsstamps.StampProtoTypeDNSCrypt}
	if len(bin) < 66 {
		return stamp, errors.New("Stamp is too short")
	}
	stamp.Props = dnsstamps.ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	binLen := len(bin)
	pos := 9

	length := int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
	bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
	if colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(stamp.ServerAddrStr)
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
	}
	if colIndex >= len(stamp.ServerAddrStr)-1 {
		return stamp, errors.New("Invalid stamp (empty port)")
	}
	ipOnly := stamp.ServerAddrStr[:colIndex]
	portOnly := stamp.ServerAddrStr[colIndex+1:]
	log.D("++++++++++++ ipp: %s %s", ipOnly, portOnly)
	if _, err := strconv.ParseUint(portOnly, 10, 16); err != nil {
		return stamp, errors.New("Invalid stamp (port range)")
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return stamp, errors.New("Invalid stamp (IP address)")
	}

	length = int(bin[pos])
	if 1+length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerPk = bin[pos : pos+length]
	pos += length

	length = int(bin[pos])
	if length >= binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// id(u8)=0x02 props addrLen(1) serverAddr hashLen(1) hash providerNameLen(1) providerName pathLen(1) path

func newDoHServerStamp(bin []byte) (ServerStamp, error) {
	return ServerStamp{}, errors.New("not implemented")
}

// id(u8)=0x81 addrLen(1) serverAddr

func newDNSCryptRelayStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: dnsstamps.StampProtoTypeDNSCryptRelay}
	if len(bin) < 13 {
		return stamp, errors.New("Stamp is too short")
	}
	binLen := len(bin)
	pos := 1
	length := int(bin[pos])
	if 1+length > binLen-pos {
		return stamp, errors.New("Invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	colIndex := strings.LastIndex(stamp.ServerAddrStr, ":")
	bracketIndex := strings.LastIndex(stamp.ServerAddrStr, "]")
	if colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		colIndex = len(stamp.ServerAddrStr)
		stamp.ServerAddrStr = fmt.Sprintf("%s:%d", stamp.ServerAddrStr, DefaultPort)
	}
	if colIndex >= len(stamp.ServerAddrStr)-1 {
		return stamp, errors.New("Invalid stamp (empty port)")
	}
	ipOnly := stamp.ServerAddrStr[:colIndex]
	portOnly := stamp.ServerAddrStr[colIndex+1:]
	if _, err := strconv.ParseUint(portOnly, 10, 16); err != nil {
		return stamp, errors.New("Invalid stamp (port range)")
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return stamp, errors.New("Invalid stamp (IP address)")
	}
	if pos != binLen {
		return stamp, errors.New("Invalid stamp (garbage after end)")
	}
	return stamp, nil
}

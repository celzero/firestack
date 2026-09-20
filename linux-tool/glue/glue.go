package glue

import (
	"encoding/binary"
	"log"
	"syscall"
	"unsafe"

	"github.com/celzero/firestack/intra"
	"github.com/celzero/firestack/intra/backend"
)

type MyBridge struct {
	PIDCSV string
	TIDCSV string
}

// implement intra.log.Console
func (bridge *MyBridge) Log(level int32, msg string) {
	log.Printf("log level %d, %s", level, msg)
}

// implement intra.backend.Controller
func (bridge *MyBridge) Bind4(who, addrport string, fd int) {}
func (bridge *MyBridge) Bind6(who, addrport string, fd int) {}
func (bridge *MyBridge) Protect(who string, fd int)         {}

// implement intra.SocketListener
func (bridge *MyBridge) Preflow(protocol, uid int32, src, dst, domains string) *intra.PreMark {
	return &intra.PreMark{
		UID:       "-1",
		IsUidSelf: false,
	}
}
func (bridge *MyBridge) Flow(protocol, uid int32, src, dst, origdsts, domains, probableDomains, blocklists string) *intra.Mark {
	return &intra.Mark{
		PIDCSV: bridge.PIDCSV,
		CID:    "0",
		UID:    "-1",
	}
}
func (bridge *MyBridge) Inflow(protocol, uid int32, src, dst string) *intra.Mark {
	return &intra.Mark{
		PIDCSV: bridge.PIDCSV,
		CID:    "0",
		UID:    "-1",
	}
}
func (bridge *MyBridge) OnSocketClosed(*intra.SocketSummary) {}

// implement intra.backend.ResolverListener
func (bridge *MyBridge) OnDNSAdded(id string)   {}
func (bridge *MyBridge) OnDNSRemoved(id string) {}
func (bridge *MyBridge) OnDNSStopped()          {}

// implement intra.backend.DNSListener
func (bridge *MyBridge) OnQuery(uid, domain string, qtyp int) *backend.DNSOpts {
	return &backend.DNSOpts{
		PIDCSV:    bridge.PIDCSV,
		IPCSV:     "",
		TIDCSV:    bridge.TIDCSV,
		TIDSECCSV: "",
		NOBLOCK:   false,
	}
}
func (bridge *MyBridge) OnResponse(*backend.DNSSummary) {}

// implement intra.backend.ServerListener
func (bridge *MyBridge) SvcRoute(sid, pid, network, sipport, dipport string) *backend.Tab {
	return &backend.Tab{
		CID:   "0",
		Block: false,
	}
}
func (bridge *MyBridge) OnSvcComplete(*backend.ServerSummary) {}

// implement intra.backend.ProxyListener
func (bridge *MyBridge) OnProxyAdded(id string)   {}
func (bridge *MyBridge) OnProxyRemoved(id string) {}
func (bridge *MyBridge) OnProxyStopped(id string) {}
func (bridge *MyBridge) OnProxiesStopped()        {}

func Ioctl(fd int, req uint64, data []byte) (int, error) {
	p := unsafe.Pointer(&data[0])
	r1, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(p))
	if errno == 0 {
		return int(r1), nil
	} else {
		return int(r1), errno
	}
}
func OpenTUN(name string) (int, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 600)
	if err != nil {
		return fd, err
	}
	var req [64]byte
	copy(req[:15], []byte(name))
	flags := uint16(syscall.IFF_TUN | syscall.IFF_NO_PI)
	binary.NativeEndian.PutUint16(req[16:], flags)
	_, err = Ioctl(fd, syscall.TUNSETIFF, req[:])
	if err != nil {
		defer syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}
func GenFDCmsg(fds []uint32) []byte {
	cmsgLen := 16 + len(fds)*4
	cmsg := make([]byte, cmsgLen)
	binary.NativeEndian.PutUint64(cmsg[:], uint64(cmsgLen))
	binary.NativeEndian.PutUint32(cmsg[8:], syscall.SOL_SOCKET)
	binary.NativeEndian.PutUint32(cmsg[12:], syscall.SCM_RIGHTS)

	offset := 16
	for _, v := range fds {
		binary.NativeEndian.PutUint32(cmsg[offset:], v)
		offset += 4
	}
	return cmsg
}

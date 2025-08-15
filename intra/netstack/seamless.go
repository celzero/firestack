package netstack

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"syscall"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// SnapLen is the maximum bytes of a packet to be saved. Packets with a length
// less than or equal to snapLen will be saved in their entirety. Longer
// packets will be truncated to snapLen.
const SnapLen uint32 = 2048 // in bytes; some sufficient value

var errNoFdSwapper = errors.New("magiclink: no FdSwapper")

type FdSwapper interface {
	// Swap closes existing FDs; uses new fd.
	Swap(fd int) error
	// Dispose closes all existing FDs.
	Dispose() error
	// Stat returns EpStat (fd, age, read, written, lastRead, lastWrite).
	Stat() EpStat
}

type EpStat struct {
	// Fd is the file descriptor of the endpoint.
	Fd int
	// Alive indicates whether the endpoint is alive.
	Alive bool
	// Age is the age of the endpoint.
	Age string
	// Read is the number of bytes read from the endpoint.
	Read string
	// Written is the number of bytes written to the endpoint.
	Written string
	// LastRead is the last time the endpoint was read from.
	LastRead string
	// LastWrite is the last time the endpoint was written to.
	LastWrite string
}

func (s EpStat) String() string {
	if s.Fd == 0 {
		return "<nil>"
	}
	return fmt.Sprintf("Fd: %d,Alive: %t,Age: %s,R: %s,W: %s,LastRead: %s,LastWrite: %s",
		s.Fd,
		s.Alive,
		s.Age,
		s.Read,
		s.Written,
		s.LastRead,
		s.LastWrite)
}

type SeamlessEndpoint interface {
	stack.LinkEndpoint
	FdSwapper
}

type magiclink struct {
	e *core.Volatile[stack.LinkEndpoint]
	d *core.Volatile[stack.NetworkDispatcher]
	FdSwapper
}

var _ stack.LinkEndpoint = (*magiclink)(nil)
var _ stack.NetworkDispatcher = (*magiclink)(nil)
var _ stack.GSOEndpoint = (*magiclink)(nil)
var _ FdSwapper = (*magiclink)(nil)

// ref: github.com/google/gvisor/blob/91f58d2cc/pkg/tcpip/sample/tun_tcp_echo/main.go#L102
func NewEndpoint(dev, mtu int, sink io.WriteCloser) (ep SeamlessEndpoint, err error) {
	defer func() {
		if err != nil {
			_ = syscall.Close(dev)
		}
		log.I("netstack: new endpoint(fd:%d / mtu:%d); err? %v", dev, mtu, err)
	}()

	umtu := uint32(mtu)
	opt := Options{
		FDs: []int{dev},
		MTU: umtu,
	}

	if ep, err = newFdbasedInjectableEndpoint(&opt); err != nil {
		return nil, err
	}
	// ref: github.com/google/gvisor/blob/aeabb785278/pkg/tcpip/link/sniffer/sniffer.go#L111-L131
	return snoop(ep, sink)
}

func snoop(ep SeamlessEndpoint, sink io.WriteCloser) (SeamlessEndpoint, error) {
	if sink == nil {
		return ep, nil
	}
	// TODO: MTU instead of SnapLen? Must match pcapsink.begin()
	if link, err := NewSnoopyEndpoint(ep, sink); err != nil {
		return nil, err
	} else {
		v := core.NewVolatile[stack.LinkEndpoint](link)
		d := core.NewZeroVolatile[stack.NetworkDispatcher]()
		return &magiclink{v, d, ep}, nil
	}
}

func Pcap2Stdout(y bool) (ok bool) {
	if y {
		ok = LogPackets.CompareAndSwap(0, 1)
	} else {
		ok = LogPackets.CompareAndSwap(1, 0)
	}
	log.I("netstack: pcap stdout(%t): done?(%t)", y, ok)
	return
}

func Pcap2File(y bool) (ok bool) {
	if y {
		ok = WritePCAP.CompareAndSwap(0, 1)
	} else {
		ok = WritePCAP.CompareAndSwap(1, 0)
	}
	log.I("netstack: pcap file(%t): done?(%t)", y, ok)
	return
}

// PCAP logging modes:
// - stdout: packets are logged to stdout
// - file: packets are logged to a file
// - none: no packets are logged
func PcapModes() string {
	var modes []string
	if LogPackets.Load() == 1 {
		modes = append(modes, "stdout")
	}
	if WritePCAP.Load() == 1 {
		modes = append(modes, "file")
	}
	if len(modes) == 0 {
		return "none"
	}
	return strings.Join(modes, ",")
}

// Swap implements FdSwapper.
func (l *magiclink) Swap(fd int) error {
	if l.FdSwapper == nil {
		return errNoFdSwapper
	}

	err := l.FdSwapper.Swap(fd)
	if errors.Is(err, errNeedsNewEndpoint) {
		umtu := uint32(l.MTU())
		opt := Options{
			FDs: []int{fd},
			MTU: umtu,
		}

		ep, err := newFdbasedInjectableEndpoint(&opt)
		if err != nil {
			log.E("netstack: magic(%d); err %v", fd, err)
			return err
		}

		if old := l.e.Swap(ep); old != nil {
			core.Go("magic."+strconv.Itoa(fd), old.Close)
		}

		d := l.d.Load()
		if d == nil {
			ep.Attach(nil) // attach the new endpoint to the dispatcher
		} else {
			ep.Attach(l) // attach the new endpoint to the existing dispatcher
		}
		logei(d == nil)("netstack: %d magic(mtu: %d); new ep... dispatch? %t", fd, umtu, d != nil)
	}

	return err
}

func (l *magiclink) MTU() uint32 {
	if e := l.e.Load(); e != nil {
		return e.MTU()
	}
	return 0
}

func (l *magiclink) SetMTU(mtu uint32) {
	if e := l.e.Load(); e != nil {
		e.SetMTU(mtu)
	}
}

func (l *magiclink) MaxHeaderLength() uint16 {
	if e := l.e.Load(); e != nil {
		return e.MaxHeaderLength()
	}
	return 0
}

func (l *magiclink) LinkAddress() tcpip.LinkAddress {
	if e := l.e.Load(); e != nil {
		return e.LinkAddress()
	}
	return ""
}

func (l *magiclink) SetLinkAddress(addr tcpip.LinkAddress) {
	if e := l.e.Load(); e != nil {
		e.SetLinkAddress(addr)
	}
}

func (l *magiclink) Capabilities() stack.LinkEndpointCapabilities {
	if e := l.e.Load(); e != nil {
		return e.Capabilities()
	}
	return 0
}

func (l *magiclink) Attach(dispatcher stack.NetworkDispatcher) {
	l.d.Store(dispatcher) // update the dispatcher
	if e := l.e.Load(); e != nil {
		if dispatcher == nil {
			e.Attach(nil) // detach
		} else {
			e.Attach(l)
		}
	}
}

func (l *magiclink) IsAttached() bool {
	if e := l.e.Load(); e != nil {
		return e.IsAttached()
	}
	return false
}

func (l *magiclink) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if d := l.d.Load(); d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

func (l *magiclink) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if d := l.d.Load(); d != nil {
		d.DeliverLinkPacket(protocol, pkt)
	}
}

func (l *magiclink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if e := l.e.Load(); e != nil {
		return e.WritePackets(pkts)
	}
	return 0, &tcpip.ErrInvalidEndpointState{}
}

func (l *magiclink) Wait() {
	if e := l.e.Load(); e != nil {
		e.Wait()
	}
}

func (l *magiclink) ARPHardwareType() header.ARPHardwareType {
	if e := l.e.Load(); e != nil {
		return e.ARPHardwareType()
	}
	return 0
}

func (l *magiclink) AddHeader(pkt *stack.PacketBuffer) {
	if e := l.e.Load(); e != nil {
		e.AddHeader(pkt)
	}
}

func (l *magiclink) ParseHeader(pkt *stack.PacketBuffer) bool {
	if e := l.e.Load(); e != nil {
		return e.ParseHeader(pkt)
	}
	return false
}

func (l *magiclink) Close() {
	if e := l.e.Load(); e != nil {
		e.Close()
	}
}

func (l *magiclink) SetOnCloseAction(f func()) {
	if e := l.e.Load(); e != nil {
		e.SetOnCloseAction(f)
	}
}

func (l *magiclink) GSOMaxSize() uint32 { return 0 }

// SupportedGSO returns the supported segmentation offloading.
func (l *magiclink) SupportedGSO() stack.SupportedGSO { return stack.GSONotSupported }

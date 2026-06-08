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
	glog "gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Clearing endpoint on Dispose will result in all stack.Linkpoint APIs
// returning zero values (which may trip netstack?)
const clearEndpointOnDispose = false

type FdSwapper interface {
	// Swap closes existing FDs; uses new fd.
	Swap(fd, mtu int) error
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
	e *core.Volatile[SeamlessEndpoint]
	d *core.Volatile[stack.NetworkDispatcher]
	s io.WriteCloser
}

var _ stack.LinkEndpoint = (*magiclink)(nil)
var _ stack.NetworkDispatcher = (*magiclink)(nil)
var _ stack.GSOEndpoint = (*magiclink)(nil)
var _ SeamlessEndpoint = (*magiclink)(nil)

var errMissingSink = errors.New("magic: pcap sink is nil")

// ref: github.com/google/gvisor/blob/91f58d2cc/pkg/tcpip/sample/tun_tcp_echo/main.go#L102
func NewEndpoint(dev, mtu int, sink io.WriteCloser) (ep SeamlessEndpoint, err error) {
	defer func() {
		if err != nil {
			_ = syscall.Close(dev)
		}
		log.I("netstack: new endpoint(fd:%d / mtu:%d); err? %v", dev, mtu, err)
	}()

	if sink == nil {
		return nil, errMissingSink
	}

	umtu := uint32(mtu)
	opt := Options{
		FDs: []int{dev},
		MTU: umtu,
	}

	if ep, err = newFdbasedInjectableEndpoint(&opt); err != nil {
		return nil, err
	}
	// ref: github.com/google/gvisor/blob/aeabb785278/pkg/tcpip/link/sniffer/sniffer.go#L111-L131
	v := core.NewVolatile(ep)
	d := core.NewZeroVolatile[stack.NetworkDispatcher]()

	return &magiclink{e: v, d: d /*nil*/, s: sink}, nil
}

func DebugLog(y bool) (l string) {
	if y {
		glog.SetLevel(glog.Debug)
	} else {
		glog.SetLevel(glog.Info)
	}
	return glog.Log().Level.String()
}

func Pcap2Stdout(y bool) (ok bool) {
	if y {
		ok = logPackets.CompareAndSwap(0, 1)
	} else {
		ok = logPackets.CompareAndSwap(1, 0)
	}
	log.I("netstack: pcap stdout(%t): done?(%t)", y, ok)
	return
}

func Pcap2File(y bool) (ok bool) {
	if y {
		ok = writePCAP.CompareAndSwap(0, 1)
	} else {
		ok = writePCAP.CompareAndSwap(1, 0)
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
	if logPackets.Load() == 1 {
		modes = append(modes, "stdout")
	}
	if writePCAP.Load() == 1 {
		modes = append(modes, "file")
	}
	if len(modes) == 0 {
		return "none"
	}
	return strings.Join(modes, ",")
}

// Swap implements SeamlessEndpoint.
func (l *magiclink) Swap(fd, mtu int) (err error) {
	e := l.e.Load()
	hasSwappedFd := false
	needsNewEndpoint := e == nil
	if e != nil {
		err = e.Swap(fd, mtu)
		hasSwappedFd = err == nil
		needsNewEndpoint = errors.Is(err, errNeedsNewEndpoint)
	}

	if hasSwappedFd || !needsNewEndpoint {
		logei(!hasSwappedFd)("netstack: magic(%d); swap: ok? %t; err? %v",
			fd, hasSwappedFd, err)
		return err
	}

	umtu := uint32(mtu)
	opt := Options{
		FDs: []int{fd},
		MTU: umtu,
	}

	ep, err := newFdbasedInjectableEndpoint(&opt)
	if err != nil || ep == nil {
		log.E("netstack: magic(%d); swap: ep missing? %t; err %v", fd, ep == nil, err)
		return core.OneErr(err, errMissingEp)
	}

	// attach eventually runs a dispatchLoop which kickstarts the endpoint's
	// delivery of packets to netstack's dispatcher.
	d := l.d.Load()
	if d == nil {
		ep.Attach(nil) // attach the new endpoint to the dispatcher
	} else {
		ep.Attach(l) // attach the new endpoint to the existing dispatcher
	}

	// swap endpoints after the dispatchLoop has had the chance to start
	// to avoid cases where clients end up calling ep.Wait() before dispatchLoop
	// could begin (as it is responsible for keeping ep alive)
	if old := l.e.Tango(ep); old != nil {
		// Close signals the dispatch loop to stop via stopfd.
		// Wait ensures the goroutine has fully exited and all
		// FDs/buffers are released. Without Wait, the goroutine
		// can linger, leaking resources.
		core.Go("magic.close."+strconv.Itoa(fd), func() {
			old.Close()
			old.Wait()
		})
	}

	logei(d == nil)("netstack: magic(%d) mtu: %d; swap: new ep... dispatch? %t",
		fd, umtu, d != nil)

	return nil
}

// Dispose implements SeamlessEndpoint.
func (l *magiclink) Dispose() error {
	if e := l.e.Load(); e != nil {
		if clearEndpointOnDispose {
			// will result in stack.LinkEndpoint impls return zero values
			// unsure if this will trip netstack in to thinking if this
			// endpoint is kaput, when in reality, this endpoint can swap
			// in a healthy endpoint at a later point in time, which then
			// we'd expect netstack to use as expected.
			l.e.Store(nil)
		}
		return e.Dispose()
	}
	log.W("netstack: magic: dispose; no endpoint")
	return nil
}

// Stat implements SeamlessEndpoint.
func (l *magiclink) Stat() EpStat {
	if e := l.e.Load(); e != nil {
		return e.Stat()
	}
	return EpStat{}
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
	log.I("netstack: magic: attach dispatcher? %t", dispatcher == nil)
}

func (l *magiclink) IsAttached() bool {
	if e := l.e.Load(); e != nil {
		return e.IsAttached()
	}
	return false
}

func (l *magiclink) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	l.DumpPacket(DirectionRecv, protocol, pkt)
	if d := l.d.Load(); d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
		return
	}
	// release packet buffer when no dispatcher is available. The endpoint's dispatch
	// increments the refcount before calling this method, expecting us to release it.
	if pkt != nil {
		pkt.DecRef()
	}
	log.E("netstack: magic: deliver network packet (sz: %d); no dispatcher, packet released", pkt.Size())
}

// unused
func (l *magiclink) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	l.DumpPacket(DirectionRecv, protocol, pkt)
	if d := l.d.Load(); d != nil {
		d.DeliverLinkPacket(protocol, pkt)
		return
	}
	// release packet buffer when no dispatcher is available
	if pkt != nil {
		pkt.DecRef()
	}
	log.E("netstack: magic: deliver link packet (sz: %d); no dispatcher, packet released", pkt.Size())
}

func (l *magiclink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if l.doPCAP() {
		for _, pkt := range pkts.AsSlice() {
			if pkt != nil { // nilaway
				l.DumpPacket(DirectionSend, pkt.NetworkProtocolNumber, pkt)
			}
		}
	}
	if e := l.e.Load(); e != nil {
		return e.WritePackets(pkts)
	}
	log.E("netstack: magic: write packets; no endpoint")
	return 0, &tcpip.ErrNotPermitted{}
}

func (l *magiclink) Wait() {
	if e := l.e.Load(); e != nil {
		if e.IsAttached() {
			e.Wait() // may panic in case of WaitGroup reuse issues
		} else {
			log.W("netstack: magic: wait; dispatcher not attached; has dispatcher? %t", l.d.Load() != nil)
		}
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

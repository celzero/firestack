package netstack

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
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

var (
	errNoFdSwapper = errors.New("linkFdSwap: no FdSwapper")
)

type linkSwap struct {
	sync.Mutex
	e stack.LinkEndpoint
	FdSwapper
}

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
		return &linkSwap{sync.Mutex{}, link, ep}, nil
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
func (l *linkSwap) Swap(fd int) error {
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
		if ep, err := newFdbasedInjectableEndpoint(&opt); err == nil {
			l.Lock()
			core.Go("linkFdSwap."+strconv.Itoa(fd), l.e.Close)
			l.e = ep
			l.Unlock()
		} else {
			log.E("netstack: linkFdSwap(%d); err %v", fd, err)
			return err
		}
	}

	return err
}

func (l *linkSwap) MTU() uint32 {
	l.Lock()
	e := l.e
	l.Unlock()
	return e.MTU()
}

func (l *linkSwap) SetMTU(mtu uint32) {
	l.Lock()
	e := l.e
	l.Unlock()
	e.SetMTU(mtu)
}

func (l *linkSwap) MaxHeaderLength() uint16 {
	l.Lock()
	e := l.e
	l.Unlock()
	return e.MaxHeaderLength()
}

func (l *linkSwap) LinkAddress() tcpip.LinkAddress {
	l.Lock()
	e := l.e
	l.Unlock()
	return e.LinkAddress()
}

func (l *linkSwap) SetLinkAddress(addr tcpip.LinkAddress) {
	l.Lock()
	e := l.e
	l.Unlock()
	e.SetLinkAddress(addr)
}

func (l *linkSwap) Capabilities() stack.LinkEndpointCapabilities {
	l.Lock()
	e := l.e
	l.Unlock()
	return e.Capabilities()
}

func (l *linkSwap) Attach(dispatcher stack.NetworkDispatcher) {
	l.Lock()
	e := l.e
	l.Unlock()
	e.Attach(dispatcher)
}

func (l *linkSwap) IsAttached() bool {
	l.Lock()
	e := l.e
	l.Unlock()
	return e.IsAttached()
}

func (l *linkSwap) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	l.Lock()
	e := l.e
	l.Unlock()
	return e.WritePackets(pkts)
}

func (l *linkSwap) Wait() {
	l.Lock()
	e := l.e
	l.Unlock()
	e.Wait()
}

func (l *linkSwap) ARPHardwareType() header.ARPHardwareType {
	l.Lock()
	e := l.e
	l.Unlock()
	return e.ARPHardwareType()
}

func (l *linkSwap) AddHeader(pkt *stack.PacketBuffer) {
	l.Lock()
	e := l.e
	l.Unlock()
	e.AddHeader(pkt)
}

func (l *linkSwap) ParseHeader(pkt *stack.PacketBuffer) bool {
	l.Lock()
	e := l.e
	l.Unlock()
	return e.ParseHeader(pkt)
}

func (l *linkSwap) Close() {
	l.Lock()
	e := l.e
	l.Unlock()
	e.Close()
}

func (l *linkSwap) SetOnCloseAction(f func()) {
	l.Lock()
	e := l.e
	l.Unlock()
	e.SetOnCloseAction(f)
}

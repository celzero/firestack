// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"net"
	"net/netip"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/rpn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

var (
	anyaddr4 = netip.IPv4Unspecified()
	anyaddr6 = netip.IPv6Unspecified()
)

// exit64 is a proxy that always dials out to the internet
// over well-known preset public NAT64 prefixes.
type exit64 struct {
	NoDNS
	ProtoAgnostic
	SkipRefresh
	GWNoVia

	rpn.RpnForever
	rpn.RpnStateless
	rpn.RpnCountryless

	outbound *protect.RDial // outbound dialer
	addr     string
	since    time.Time
	status   *core.Volatile[int]
	done     context.CancelFunc
}

var _ RpnAcc = (*exit64)(nil)

// NewExit64Proxy returns a new exit64 proxy.
func NewExit64Proxy(ctx context.Context, c protect.Controller) *exit64 {
	ctx, done := context.WithCancel(ctx)
	h := &exit64{
		addr: "127.64.64.127:6464",
		// "Exit" as "id" to have all its sockets "protected"
		outbound: protect.MakeNsRDial(Exit, ctx, c),
		status:   core.NewVolatile(TUP),
		since:    time.Now(),
		done:     done,
	}
	return h
}

// Handle implements Proxy.
func (h *exit64) Handle() uintptr {
	return core.Loc(h)
}

// DialerHandle implements Proxy.
func (h *exit64) DialerHandle() uintptr {
	return core.Loc(h.outbound)
}

// Dial implements Proxy.
func (h *exit64) Dial(network, addr string) (protect.Conn, error) {
	return h.dial(network, "", addr)
}

// DialBind implements Proxy.
func (h *exit64) DialBind(network, local, remote string) (protect.Conn, error) {
	return h.dial(network, local, remote)
}

func (h *exit64) dial(network, local, remote string) (protect.Conn, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}

	addr64 := addr4to6(remote)
	local64 := anyaddr4to6(local)
	if len(addr64) <= 0 || (len(local) > 0 && len(local64) <= 0) {
		return nil, errNoAuto464XLAT
	}

	// exit64 always splits
	c, err := localDialStrat(h.outbound, network, local64, addr64)
	defer localDialStatus(h.status, err)

	kaenabled := maybeKeepAlive(c)
	logei(err)("proxy: exit64: dial(%s) %s via %s to %s, ka? %t; err? %v",
		network, local64, remote, addr64, kaenabled, err)

	return c, err
}

// Announce implements Proxy.
func (h *exit64) Announce(network, local string) (protect.PacketConn, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	var local64 string
	if ipp, _ := netip.ParseAddrPort(local); ipp.IsValid() {
		if ipp.Addr().Is4() {
			local64 = netip.AddrPortFrom(netip.IPv6Unspecified(), ipp.Port()).String()
		} else {
			local64 = local
		}
	}
	if len(local64) <= 0 {
		return nil, errNoAuto464XLAT
	}

	c, err := dialers.ListenPacket(h.outbound, network, local64)
	defer localDialStatus(h.status, err)

	logei(err)("proxy: exit64: announce(%s) via %s on %s; err? %v", network, local64, local, err)
	return c, err
}

// Accept implements Proxy.
func (h *exit64) Accept(network, local string) (protect.Listener, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	var local64 string
	if ipp, _ := netip.ParseAddrPort(local); ipp.IsValid() {
		if ipp.Addr().Is4() {
			local64 = netip.AddrPortFrom(netip.IPv6Unspecified(), ipp.Port()).String()
		} else {
			local64 = local
		}
	}
	if len(local64) <= 0 {
		return nil, errNoAuto464XLAT
	}

	l, err := dialers.Listen(h.outbound, network, local)
	defer localDialStatus(h.status, err)

	logei(err)("proxy: exit64: accept(%s) via %s on %s; err? %v", network, local64, local, err)
	return l, err
}

// Probe implements Proxy.
func (h *exit64) Probe(network, local string) (protect.PacketConn, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	var local64 string
	if ipp, _ := netip.ParseAddrPort(local); ipp.IsValid() {
		if ipp.Addr().Is4() {
			local64 = netip.AddrPortFrom(netip.IPv6Unspecified(), ipp.Port()).String()
		} else {
			local64 = local
		}
	}
	if len(local64) <= 0 {
		return nil, errNoAuto464XLAT
	}

	c, err := dialers.Probe(h.outbound, network, local)
	defer localDialStatus(h.status, err)

	logei(err)("proxy: exit64: probe(%s) via %s on %s; err? %v", network, local64, local, err)
	return c, err
}

// Dialer implements Proxy.
func (h *exit64) Dialer() protect.RDialer {
	return h
}

// ID implements Proxy.
func (h *exit64) ID() string {
	return Rpn64
}

// Type implements Proxy.
func (h *exit64) Type() string {
	return INTERNET
}

// Router implements Proxy.
func (h *exit64) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *exit64) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

// GetAddr implements Proxy.
func (h *exit64) GetAddr() string {
	return h.addr
}

// Status implements Proxy.
func (h *exit64) Status() int {
	return h.status.Load()
}

// Since implements x.Proxy.
func (h *exit64) Pause() bool {
	st := h.status.Load()
	if st == END {
		log.W("proxy: exit64: pause called when stopped")
		return false
	}

	ok := h.status.Cas(st, TPU)
	logeif(!ok)("proxy: exit64: paused? %t", ok)
	return ok
}

// Resume implements x.Proxy.
func (h *exit64) Resume() bool {
	st := h.status.Load()
	if st != TPU {
		log.W("proxy: exit64: resume called when not paused; status %d", st)
		return false
	}

	ok := h.status.Cas(st, TUP)
	go h.Refresh() // no-op since SkipRefresh
	logeif(!ok)("proxy: exit64: resumed? %t", ok)
	return ok
}

// Stop implements Proxy.
func (h *exit64) Stop() error {
	h.status.Store(END)
	h.done()
	log.I("proxy: exit64: stopped")
	return nil
}

// Who implements x.RpnAcc.
func (h *exit64) Who() string {
	return Rpn64
}

// Provider implements RpnAcc.
func (*exit64) ProviderID() string { return Rpn64 }

// go.dev/play/p/GtLCDAXeeLJ
func addr4to6(addr string) string {
	// check if addr is an IPv4 address
	ipport, err := netip.ParseAddrPort(addr)
	if err != nil { // hostname?
		resolved := dialers.For(addr)
		ok := len(resolved) > 0

		for _, ip := range resolved {
			if !ip.IsValid() || ip.Is6() {
				continue
			}
			ipport = netip.AddrPortFrom(ip, ipport.Port())
			break // break on first valid IPv4 ipport
		}

		logeif(!ok)("proxy: auto: exit64: addr64: is host? %s; chosen? %v, resolved? %v; err: %v",
			addr, ipport, resolved, err)

		if !ipport.IsValid() {
			return ""
		}
	}

	ip4 := ipport.Addr()
	if !ip4.Is4() {
		log.VV("proxy: auto: exit64: addr64: chosen addr not v4(%s)", addr)
		return ""
	}
	// embed IPv4 in IPv6
	ippre := core.ChooseOne(rpn.Net6to4)
	ip6 := ip4to6(ippre, ip4)
	if !ip6.IsValid() {
		log.W("proxy: auto: exit64: addr64: failed to embed(%s) in v6(%s)", ip4, ippre)
		return ""
	}
	return netip.AddrPortFrom(ip6, ipport.Port()).String()
}

func ip4to6(prefix96 netip.Prefix, ip4 netip.Addr) netip.Addr {
	if !prefix96.IsValid() || !ip4.IsValid() {
		return netip.Addr{}
	}
	startingAddress := prefix96.Masked().Addr()
	addrLen := startingAddress.BitLen() / 8 // == 128 / 8 == 16
	prefixLen := prefix96.Bits() / 8        // == 96 / 8 == 12
	hostLen := (addrLen - prefixLen)        // == 16 - 12 == 4
	s6 := startingAddress.As16()
	s4 := ip4.As4()
	n := copy(s6[prefixLen:], s4[:hostLen])
	if n != hostLen {
		log.W("proxy: auto: exit64: ip4to6(%v, %v) failed; pre:%d host:%d for net:%v ip4:%v",
			s6, s4, prefixLen, hostLen, prefix96, ip4)
		return netip.Addr{}
	}
	return netip.AddrFrom16(s6)
}

func anyaddr4to6(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return net.JoinHostPort(anyaddr6.String(), port)
	}
	return addr
}

func logeif(e bool) log.LogFn {
	if e {
		return log.E
	}
	if settings.Debug {
		return log.D
	}
	return log.N
}

func logei(err error) log.LogFn {
	if err != nil {
		return log.E
	}
	return log.I
}

// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT
//
//    Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

// from: github.com/WireGuard/wireguard-go/blob/5819c6af/tun/netstack/tun.go

package ipn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/multihost"
	"github.com/celzero/firestack/intra/ipn/wg"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// github.com/WireGuard/wireguard-go/blob/12269c276/device/queueconstants_android.go#L14
	// epsize is the size of the channel endpoint.
	epsize = 4096
	// eventssize is the size of the events channel.
	eventssize = 64
	// wgnic is the id of the WireGuard network interface.
	wgnic = 999
	// missing wg interface address.
	noaddr = ""
	// min mtu for ipv6
	minmtu6 = 1280
)

type wgtun struct {
	id             string            // id
	addrs          []netip.Prefix    // interface addresses
	allowed        []netip.Prefix    // allowed ips (peers)
	remote         *multihost.MH     // remote endpoints
	status         int               // status of this interface
	stack          *stack.Stack      // stack fakes tun device for wg
	ep             *channel.Endpoint // reads and writes packets to/from stack
	incomingPacket chan *buffer.View // pipes ep writes to wg
	events         chan tun.Event    // wg specific tun (interface) events
	mtu            int               // mtu of this interface
	dns            *multihost.MH     // dns resolver for this interface
	reqbarrier     *core.Barrier     // request barrier for dns lookups
	once           sync.Once         // exec fn exactly once
	hasV4, hasV6   bool              // interface has ipv4/ipv6 routes?
}

type wgconn interface {
	conn.Bind
	RemoteAddr() netip.AddrPort
}

var _ WgProxy = (*wgproxy)(nil)

type wgproxy struct {
	*wgtun
	*device.Device
	wgep wgconn
	hc   *http.Client   // exported http client
	rd   *protect.RDial // exported rdialer
}

type WgProxy interface {
	Proxy
	tun.Device
	canUpdate(txt string) bool
	IpcSet(txt string) error
}

// Dial implements WgProxy
func (h *wgproxy) Dial(network, address string) (c protect.Conn, err error) {
	// ProxyDial resolves address if needed; then dials into all resolved ips.
	return dialers.ProxyDial(h.wgtun, network, address)
}

// Announce implements Proxy.
func (h *wgproxy) Announce(network, local string) (protect.PacketConn, error) {
	if h.status == END {
		return nil, errProxyStopped
	}
	return nil, errAnnounceNotSupported
}

// BatchSize implements WgProxy
func (w *wgproxy) BatchSize() int {
	return w.wgtun.BatchSize()
}

// Close implements WgProxy
func (w *wgproxy) Close() error {
	// w.wgtun.Close() called by device.Close()?
	w.Device.Close()
	return nil
}

// Stop implements ipn.Proxy
func (w *wgproxy) Stop() error {
	log.I("proxy: wg: stopping(%s); status(%d)", w.id, w.status)
	return w.Close()
}

// GetAddr implements ipn.Proxy
func (h *wgproxy) GetAddr() string {
	dst := h.wgep.RemoteAddr()
	if !dst.IsValid() {
		return noaddr
	}
	return dst.String()
}

// Refresh implements ipn.Proxy
func (w *wgproxy) Refresh() (err error) {
	n := w.dns.Refresh()
	if peers := w.remote; peers != nil {
		peers.Refresh() // peers are also refreshed by w.Device.Up()
	}
	if err = w.Device.Down(); err != nil {
		log.E("proxy: wg: !refresh(%s): down: %v", w.id, err)
		return
	}
	if err = w.Device.Up(); err != nil {
		log.E("proxy: wg: !refresh(%s): up: %v", w.id, err)
		return
	}
	// not required since wgconn:NewBind() is namespace aware
	// bindok := bindWgSockets(w.ID(), w.wgdev, w.ctl)
	log.I("proxy: wg: refresh(%s) done; len(dns): %d", w.id, n)
	return
}

func (h *wgproxy) fetch(req *http.Request) (resp *http.Response, err error) {
	stopped := h.status == END
	log.V("wg: %d; fetch: %s; ok? %t", h.id, req.URL, !stopped)
	if stopped {
		return nil, errProxyStopped
	}
	return h.hc.Do(req)
}

func (h *wgproxy) Dialer() *protect.RDial {
	return h.rd
}

func (w *wgproxy) canUpdate(txt string) bool {
	if w.status == END {
		log.W("proxy: wg: !canUpdate(%s): END; status(%d)", w.id, w.status)
		return false
	}

	// str copy: go.dev/play/p/eO814kGGNtO
	cptxt := txt
	ifaddrs, _, dnsh, _, mtu, err := wgIfConfigOf(&cptxt)
	if err != nil {
		log.W("proxy: wg: !canUpdate(%s): err: %v", w.id, err)
		return false
	}

	if len(ifaddrs) != len(w.addrs) {
		log.D("proxy: wg: !canUpdate(%s): len(ifaddrs) %d != %d", w.id, len(ifaddrs), len(w.addrs))
		return false
	}
	if w.mtu != mtu {
		log.D("proxy: wg: !canUpdate(%s): mtu %d != %d", w.id, mtu, w.mtu)
		return false
	}
	if dnsh != nil && !dnsh.EqualAddrs(w.dns) {
		log.D("proxy: wg: !canUpdate(%s): new/mismatched dns", w.id)
		return false
	}

	for _, inifaddr := range ifaddrs {
		var ipok bool
		for _, a := range w.addrs {
			if inifaddr.Masked() == a.Masked() {
				if inifaddr.Addr().Compare(a.Addr()) == 0 {
					ipok = true
					break
				}
			}
		}
		if !ipok {
			log.D("proxy: wg: !canUpdate(%s): new ifaddrs (%s) != (%s)", w.id, ifaddrs, w.addrs)
			return false
		}
	}
	return true
}

func wglogger(id string) *device.Logger {
	tag := WG + ":" + id
	logger := &device.Logger{
		Verbosef: log.Of(tag, log.N2),
		Errorf:   log.Of(tag, log.E2),
	}
	if settings.Debug {
		logger.Verbosef = log.Of(tag, log.V2)
	}
	return logger
}

func wgIfConfigOf(txtptr *string) (ifaddrs []netip.Prefix, allowedaddrs []netip.Prefix, dnsh, endpointh *multihost.MH, mtu int, err error) {
	txt := *txtptr
	pcfg := strings.Builder{}
	r := bufio.NewScanner(strings.NewReader(txt))
	dnsh = new(multihost.MH)
	endpointh = new(multihost.MH)
	for r.Scan() {
		line := r.Text()
		if len(line) <= 0 {
			// Blank line means terminate operation.
			if (len(ifaddrs) <= 0) || (dnsh.Len() <= 0) || (mtu <= 0) {
				err = errProxyConfig
			}
			return
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			err = fmt.Errorf("proxy: wg: failed to parse line %q", line)
			return
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.ToLower(strings.TrimSpace(v))

		// process interface config; Address, DNS, ListenPort, MTU
		// github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/src/main/java/com/wireguard/config/Interface.java#L232
		switch k {
		case "address": // may exist more than once
			if err = loadIPNets(&ifaddrs, v); err != nil {
				return
			}
		case "dns": // may exist more than once: github.com/celzero/rethink-app/issues/1298
			loadMH(dnsh, v)
		case "mtu":
			if mtu, err = strconv.Atoi(v); err != nil {
				return
			}
		case "allowed_ip": // may exist more than once
			if err = loadIPNets(&allowedaddrs, v); err != nil {
				return
			}
			// carry over allowed_ips
			log.V("proxy: wg: ifconfig: skipping key %q", k)
			pcfg.WriteString(line + "\n")
		case "endpoint": // may exist more than once
			// TODO: endpoint could be v4 or v6 or a hostname
			loadMH(endpointh, v)
			// carry over endpoints
			log.V("proxy: wg: ifconfig: skipping key %q", k)
			pcfg.WriteString(line + "\n")
		default:
			log.V("proxy: wg: ifconfig: skipping key %q", k)
			pcfg.WriteString(line + "\n")
		}
	}
	*txtptr = pcfg.String()
	if err == nil && len(ifaddrs) <= 0 || dnsh.Len() <= 0 || mtu <= 0 {
		err = errProxyConfig
	}
	return
}

func loadMH(mh *multihost.MH, v string) {
	if mh == nil {
		return
	}
	vv := strings.Split(v, ",")
	mh.Add(vv)
}

func loadIPNets(out *[]netip.Prefix, v string) (err error) {
	var ip netip.Addr
	// may be a csv: "172.1.0.2/32, 2000:db8::2/128"
	vv := strings.Split(v, ",")
	for _, str := range vv {
		var ipnet netip.Prefix
		str = strings.TrimSpace(str)
		if ip, err = netip.ParseAddr(str); err != nil {
			if ipnet, err = netip.ParsePrefix(str); err != nil {
				return
			}
			*out = append(*out, ipnet)
		} else { // add prefix to address
			if ipnet, err = ip.Prefix(ip.BitLen()); err != nil {
				return
			}
			*out = append(*out, ipnet)
		}
	}
	return
}

func bindWgSockets(id string, wgdev *device.Device, ctl protect.Controller) bool {
	var ok4, ok6 bool

	// ref: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/bind_std.go#L130
	// bind: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L180
	// protect: https://github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java#L316
	bind, _ := wgdev.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		log.E("proxy: wg: %s bind: failed to get wg socket", id)
		return false
	}

	if fd4, err := bind.PeekLookAtSocketFd4(); err != nil {
		log.W("proxy: wg: %s bind4: failed to get wg4 socket %v", id, err)
	} else {
		ctl.Bind4(id, fd4)
		ok4 = true
	}

	if fd6, err := bind.PeekLookAtSocketFd6(); err != nil {
		log.W("proxy: wg: %s bind6: failed to get wg6 socket %v", id, err)
	} else {
		ctl.Bind6(id, fd6)
		ok6 = true
	}

	return ok4 || ok6
}

// ref: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L76
func NewWgProxy(id string, ctl protect.Controller, cfg string) (WgProxy, error) {
	ifaddrs, allowedaddrs, dnsh, endpointh, mtu, err := wgIfConfigOf(&cfg)
	uapicfg := cfg
	if err != nil {
		log.E("proxy: wg: %s failed to get addrs from config %v", id, err)
		return nil, err
	}

	wgtun, err := makeWgTun(id, ifaddrs, allowedaddrs, dnsh, endpointh, mtu)
	if err != nil {
		log.E("proxy: wg: %s failed to create tun %v", id, err)
		return nil, err
	}

	wgep := wg.NewEndpoint2(id, ctl, wgtun.listener)

	wgdev := device.NewDevice(wgtun, wgep, wglogger(id))

	err = wgdev.IpcSet(uapicfg)
	if err != nil {
		log.E("proxy: wg: %s failed to ipc-set %v", id, err)
		return nil, err
	}

	// github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L99
	wgdev.DisableSomeRoamingForBrokenMobileSemantics()

	err = wgdev.Up()
	if err != nil {
		log.E("proxy: wg: %s failed init %v", id, err)
		return nil, err
	}

	// nb: call after StdNetBind conn has been "Open"ed
	// not needed for wg.NewBind; see: wg:wgconn.go
	// bindok := bindWgSockets(id, wgdev, ctl)

	w := &wgproxy{
		wgtun, // stack
		wgdev, // device
		wgep,  // endpoint
		nil,   // rdial
		nil,   // http-client
	}
	w.rd = newRDial(w)
	w.hc = newHTTPClient(w.rd)

	log.D("proxy: wg: new %s; addrs(%v) mtu(%d) / v4(%t) v6(%t)", id, ifaddrs, mtu, wgtun.hasV4, wgtun.hasV6)

	return w, nil
}

// ref: github.com/WireGuard/wireguard-go/blob/469159ecf7/tun/netstack/tun.go#L54
func makeWgTun(id string, ifaddrs, allowedaddrs []netip.Prefix, dnsm, endpointm *multihost.MH, mtu int) (*wgtun, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	// uint32(mtu) - 80 is the maximum payload size of a WireGuard packet.
	tunmtu := max(minmtu6, mtu-80) // 80 is the overhead of the WireGuard header

	s := stack.New(opts)
	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	ep := channel.New(epsize, uint32(tunmtu), "")
	t := &wgtun{
		id:             id,
		addrs:          ifaddrs,
		allowed:        allowedaddrs,
		remote:         endpointm, // may be nil
		ep:             ep,
		stack:          s,
		events:         make(chan tun.Event, eventssize),
		incomingPacket: make(chan *buffer.View, epsize),
		dns:            dnsm,
		reqbarrier:     core.NewBarrier(wgbarrierttl),
		mtu:            tunmtu,
		status:         TUP,
	}

	// see WriteNotify below
	ep.AddNotify(t)

	if err := s.CreateNIC(wgnic, ep); err != nil {
		return nil, fmt.Errorf("wg: %s create nic: %v", t.id, err)
	}

	processed := make(map[string]bool)
	for _, ipnet := range ifaddrs {
		ip := ipnet.Addr()
		if processed[ipnet.String()] {
			log.W("proxy: wg: %s skipping duplicate ip %v for ifaddr %v", t.id, ip, ipnet)
			continue
		}
		processed[ipnet.String()] = true

		var protoid tcpip.NetworkProtocolNumber
		var nsaddr tcpip.Address
		if ip.Is4() {
			protoid = ipv4.ProtocolNumber
			nsaddr = tcpip.AddrFrom4(ip.As4())
		} else if ip.Is6() {
			protoid = ipv6.ProtocolNumber
			nsaddr = tcpip.AddrFrom16(ip.As16())
		}
		ap := tcpip.AddressWithPrefix{
			Address:   nsaddr,
			PrefixLen: ipnet.Bits(),
		}
		protoaddr := tcpip.ProtocolAddress{
			Protocol:          protoid,
			AddressWithPrefix: ap,
		}
		if err := s.AddProtocolAddress(wgnic, protoaddr, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("wg: %s add addr(%v): %v", t.id, ip, err)
		}
		t.hasV4 = t.hasV4 || ip.Is4()
		t.hasV6 = t.hasV6 || ip.Is6()
		log.D("proxy: wg: %s added ifaddr(%v)", t.id, ip)
	}
	if t.hasV4 {
		s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: wgnic})
	}
	if t.hasV6 {
		s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: wgnic})
	}

	// commence the wireguard state machine
	t.events <- tun.EventUp

	log.I("proxy: wg: %s tun: created; dns[%s]; dst[%s]; mtu[%d]", t.id, dnsm, endpointm, tunmtu)

	return t, nil
}

// implements tun.Device

func (tun *wgtun) Name() (string, error) {
	return tun.id, nil
}

func (tun *wgtun) File() *os.File {
	return nil
}

func (tun *wgtun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *wgtun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		log.W("wg: %s tun: read closed", tun.id)
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		log.W("wg: %s tun: read(%d): %v", tun.id, n, err)
		return 0, err
	}

	log.V("wg: %s tun: read(%d)", tun.id, n)
	sizes[0] = n
	return 1, nil
}

func (tun *wgtun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			log.D("wg: %s tun: write: empty packet", tun.id)
			continue
		}

		sz := len(pkt)
		b := buffer.MakeWithData(pkt)
		pko := stack.PacketBufferOptions{Payload: b}
		pkb := stack.NewPacketBuffer(pko)
		defer pkb.DecRef()
		protoid := pkt[0] >> 4
		switch protoid {
		case 4: // IPv4
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb) // write to ep
		case 6: // IPv6
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb) // write to ep
		default:
			log.W("wg: %s tun: write: unknown proto %d; discard %d", tun.id, protoid, sz)
			return 0, syscall.EAFNOSUPPORT
		}
		log.V("wg: %s tun: write: sz(%d); proto %d", tun.id, sz, protoid)
	}

	return len(bufs), nil
}

// WriteNotify is called by channel notifier on readable events
// github.com/google/gvisor/blob/acf460d0d73/pkg/tcpip/link/channel/channel.go#L31
func (tun *wgtun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt.IsNil() {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	sz := view.Size()
	log.V("wg: %s tun: write: notify sz(%d)", tun.id, sz)

	select {
	case tun.incomingPacket <- view:
	default:
		e := tun.status == END
		log.W("wg: %s tun: write: closed? %t; dropped pkt; sz(%d)", tun.id, e, sz)
	}
}

func (tun *wgtun) Close() error {
	// wgproxy inherits h.status: go.dev/play/p/HeU5EvzAjnv
	if tun.status == END {
		log.W("proxy: wg: %s tun: already closed?", tun.id)
		return errProxyStopped
	}
	var err error
	tun.once.Do(func() {
		// TODO: move this to wgproxy.Close()?

		log.D("proxy: wg: %s tun: closing...", tun.id)
		tun.status = END
		tun.stack.RemoveNIC(wgnic)

		// if tun.events != nil {
		// panics; is it closed by device.Device.Close()?
		// close(tun.events) }

		if tun.incomingPacket != nil {
			close(tun.incomingPacket)
		}

		// github.com/tailscale/tailscale/blob/836f932e/wgengine/netstack/netstack.go#L223

		// stack closes the endpoint, too via nic.go#remove?
		// tun.ep.Close()
		// destroy waits for the stack to close
		tun.stack.Destroy()

		log.I("proxy: wg: %s tun: closed", tun.id)
	})
	return err
}

func (tun *wgtun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *wgtun) BatchSize() int {
	return 1
}

// Dial implements proxy.Dialer
func (h *wgtun) Dial(network, address string) (c net.Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s dial: start %s %s", h.id, network, address)

	// DialContext resolves addr if needed; then dialing into all resolved ips.
	if c, err = h.DialContext(context.TODO(), network, address); err != nil {
		h.status = TKO
	} // else: status updated by h.listener

	log.I("wg: %s dial: end %s %s; err %v", h.id, network, address, err)

	return
}

// implements Proxy

func (h *wgtun) ID() string {
	return h.id
}

func (h *wgtun) Type() string {
	return WG
}

func (h *wgtun) Router() x.Router {
	return h
}

func (h *wgtun) Status() int {
	return h.status
}

func (h *wgtun) DNS() string {
	var s string
	// prefer hostnames over IPs:
	// hostnames may resolve to different IPs on different networks;
	// tunnel could use hostnames to implement "refresh"
	for _, hostname := range h.dns.Names() {
		s += hostname + ","
	}
	if len(s) > 0 {
		log.D("wg: %s dns hostnames: %s", h.id, s)
		return strings.TrimRight(s, ",")
	}
	for _, dns := range h.dns.Addrs() {
		if dns.IsUnspecified() || !dns.IsValid() {
			continue
		}
		// may be private, link local, etc
		s += dns.Unmap().String() + ","
	}
	if len(s) > 0 {
		log.D("wg: %s dns ipaddrs: %s", h.id, s)
		return strings.TrimRight(s, ",")
	}
	return nodns
}

// Implements Router
func (h *wgtun) IP4() bool { return h.hasV4 }
func (h *wgtun) IP6() bool { return h.hasV6 }

func (h *wgtun) Contains(ipprefix string) bool {
	ip, err1 := netip.ParseAddr(ipprefix)
	if err1 != nil {
		if ipnet, err2 := netip.ParsePrefix(ipprefix); err2 != nil {
			log.W("wg: %s router: contains: invalid ip/prefix %s; errs: [%v, %v]", h.id, ipprefix, err1, err2)
			return false
		} else {
			ip = ipnet.Addr()
		}
	}

	// go.dev/play/p/wdPoNt-cqXZ
	for _, r := range h.allowed {
		y := r.Contains(ip)
		log.D("wg: %s router: contains: %s in %s? %t", h.id, ip, r, y)
		if y {
			return y
		}
	}
	return false
}

func (h *wgtun) listener(op string, err error) {
	if h.status == END {
		return
	}

	if err == nil {
		h.status = TOK
	} else if op == "r" && timedout(err) {
		// if status is "up" but writes (op == "w") have not yet happened
		// then reads ("r") are expected to timeout; so ignore them
		h.status = TZZ
	} else {
		h.status = TKO
	}
}

func timedout(err error) bool {
	x, ok := err.(net.Error)
	return ok && x.Timeout()
}

// func Stop(), Fetch(), getDialer() is impl by wgproxy

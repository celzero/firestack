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
	"time"

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

	FAST = x.WGFAST
)

type wgtun struct {
	id             string                      // id
	addrs          []netip.Prefix              // interface addresses
	allowed        []netip.Prefix              // allowed ips (peers)
	peers          map[string]any              // peer (remote endpoint) public keys
	remote         *multihost.MH               // peer (remote endpoint) addrs
	status         int                         // status of this interface
	stack          *stack.Stack                // stack fakes tun device for wg
	ep             *channel.Endpoint           // reads and writes packets to/from stack
	incomingPacket chan *buffer.View           // pipes ep writes to wg
	events         chan tun.Event              // wg specific tun (interface) events
	mtu            int                         // mtu of this interface
	dns            *multihost.MH               // dns resolver for this interface
	reqbarrier     *core.Barrier[[]netip.Addr] // request barrier for dns lookups
	once           sync.Once                   // exec fn exactly once
	hasV4, hasV6   bool                        // interface has ipv4/ipv6 routes?
	preferOffload  bool                        // UDP GRO/GSO offloads
	since          int64                       // uptime in unix millis
	latestRx       int64                       // last rx time in unix millis
	latestTx       int64                       // last tx time in unix millis
	errRx          int64                       // rx error count
	errTx          int64                       // tx error count
}

type wgconn interface {
	conn.Bind
	RemoteAddr() netip.AddrPort
}

var _ WgProxy = (*wgproxy)(nil)

type wgproxy struct {
	nofwd
	*wgtun
	*device.Device
	wgep wgconn
	hc   *http.Client   // exported http client
	rd   *protect.RDial // exported rdialer
}

type WgProxy interface {
	Proxy
	tun.Device
	update(id, txt string) bool
	IpcSet(txt string) error
}

// Dial implements WgProxy
func (h *wgproxy) Dial(network, address string) (c protect.Conn, err error) {
	// ProxyDial resolves address if needed; then dials into all resolved ips.
	return dialers.ProxyDial(h.wgtun, network, address)
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
	// bindok := bindWgSockets(w.ID(), w.remote.AnyAddr(), w.wgdev, w.ctl)
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

func preferOffload(id string) bool {
	return strings.HasPrefix(id, FAST)
}

func stripPrefixIfNeeded(id string) string {
	return strings.TrimPrefix(id, FAST)
}

// canUpdate checks if the existing tunnel can be updated in-place;
// that is, incoming interface config is compatible with the existing tunnel,
// regardless of whether peer config has changed (which can be updated in-place).
func (w *wgproxy) update(id, txt string) bool {
	const reuse = true // can update in-place; reuse existing tunnel
	const anew = false // cannot update in-place; create new tunnel
	if w.status == END {
		log.W("proxy: wg: !update(%s<>%s): END; status(%d)", id, w.id, w.status)
		return anew
	}

	incomingPrefersOffload := preferOffload(id)
	if incomingPrefersOffload != w.preferOffload {
		log.W("proxy: wg: !update(%s): preferOffload() %t != %t", id, incomingPrefersOffload, w.preferOffload)
		return anew
	}

	// str copy: go.dev/play/p/eO814kGGNtO
	cptxt := txt
	ifaddrs, allowed, peers, dnsh, peersh, mtu, err := wgIfConfigOf(w.id, &cptxt)
	if err != nil {
		log.W("proxy: wg: !update(%s): err: %v", w.id, err)
		return anew
	}

	if len(ifaddrs) != len(w.addrs) {
		log.D("proxy: wg: !update(%s): len(ifaddrs) %d != %d", w.id, len(ifaddrs), len(w.addrs))
		return anew
	}

	actualmtu := calcTunMtu(mtu)
	if w.mtu != actualmtu {
		log.D("proxy: wg: !update(%s): mtu %d != %d", w.id, actualmtu, w.mtu)
		return anew
	}
	if dnsh != nil && !dnsh.EqualAddrs(w.dns) {
		log.D("proxy: wg: !update(%s): new/mismatched dns", w.id)
		return anew
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
			log.D("proxy: wg: !update(%s): new ifaddrs (%s) != (%s)", w.id, ifaddrs, w.addrs)
			return anew
		}
	}

	// reusing existing tunnel (interface config unchanged)
	// but peer config may have changed!
	log.I("proxy: wg: update(%s): reuse; allowed: %d->%d; peers: %d->%d; dns: %d->%d; endpoint: %d->%d",
		w.id, len(w.allowed), len(allowed), len(w.peers), len(peers), w.dns.Len(), dnsh.Len(), w.remote.Len(), peersh.Len())
	w.allowed = allowed
	w.peers = peers
	w.remote = peersh // requires refresh
	w.dns = dnsh      // requires refresh

	return reuse
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

func wgIfConfigOf(id string, txtptr *string) (ifaddrs []netip.Prefix, allowedaddrs []netip.Prefix, peers map[string]any, dnsh, endpointh *multihost.MH, mtu int, err error) {
	txt := *txtptr
	pcfg := strings.Builder{}
	r := bufio.NewScanner(strings.NewReader(txt))
	dnsh = multihost.New(id + "dns")
	endpointh = multihost.New(id + "endpoint")
	peers = make(map[string]any)
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
			err = fmt.Errorf("proxy: wg: %s failed to parse line %q", id, line)
			return
		}
		untouchedv := v
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.ToLower(strings.TrimSpace(v))

		// process interface & peer config; Address, DNS, ListenPort, MTU, Allowed IPs, Endpoint
		// github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/src/main/java/com/wireguard/config/Interface.java#L232
		// github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/src/main/java/com/wireguard/config/Peer.java#L176
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
			// peer config: carry over allowed_ips
			log.D("proxy: wg: %s ifconfig: skipping key %q", id, k)
			pcfg.WriteString(line + "\n")
		case "endpoint": // may exist more than once
			// TODO: endpoint could be v4 or v6 or a hostname
			loadMH(endpointh, v)
			// peer config: carry over endpoints
			log.D("proxy: wg: %s ifconfig: skipping key %q", id, k)
			pcfg.WriteString(line + "\n")
		case "public_key":
			peers[untouchedv] = struct{}{}
			// peer config: carry over public keys
			log.D("proxy: wg: %s ifconfig: skipping key %q", id, k)
			pcfg.WriteString(line + "\n")
		default:
			log.D("proxy: wg: %s ifconfig: skipping key %q", id, k)
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
	mh.Add(vv) // vv may be host:port, ip:port, host, or ip
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

func bindWgSockets(id, addrport string, wgdev *device.Device, ctl protect.Controller) bool {
	var ok4, ok6 bool

	// ref: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/bind_std.go#L130
	// bind: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L180
	// protect: https://github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java#L316
	bind, _ := wgdev.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		log.E("proxy: wg: %s bindWgSockets: failed to get socket", id)
		return false
	}

	if fd4, err := bind.PeekLookAtSocketFd4(); err != nil {
		log.W("proxy: wg: %s bindWgSockets4: failed to get wg4 socket %v", id, err)
	} else {
		ctl.Bind4(id, addrport, fd4)
		ok4 = true
	}

	if fd6, err := bind.PeekLookAtSocketFd6(); err != nil {
		log.W("proxy: wg: %s bindWgSockets6: failed to get wg6 socket %v", id, err)
	} else {
		ctl.Bind6(id, addrport, fd6)
		ok6 = true
	}

	return ok4 || ok6
}

// ref: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L76
func NewWgProxy(id string, ctl protect.Controller, cfg string) (WgProxy, error) {
	ifaddrs, allowedaddrs, peers, dnsh, endpointh, mtu, err := wgIfConfigOf(id, &cfg)
	uapicfg := cfg
	if err != nil {
		log.E("proxy: wg: %s failed to get addrs from config %v", id, err)
		return nil, err
	}

	wgtun, err := makeWgTun(id, ifaddrs, allowedaddrs, peers, dnsh, endpointh, mtu)
	if err != nil {
		log.E("proxy: wg: %s failed to create tun %v", id, err)
		return nil, err
	}

	id = wgtun.id // has stripped prefix FAST, if any

	var wgep wgconn
	if wgtun.preferOffload {
		wgep = wg.NewEndpoint2(id, ctl, wgtun.listener)
	} else {
		wgep = wg.NewEndpoint(id, ctl, wgtun.listener)
	}

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
	// bindok := bindWgSockets(id, endpointh.AnyAddr(), wgdev, ctl)

	w := &wgproxy{
		nofwd{},
		wgtun, // stack
		wgdev, // device
		wgep,  // endpoint
		nil,   // rdial
		nil,   // http-client
	}
	w.rd = newRDial(w)
	w.hc = newHTTPClient(w.rd)

	log.D("proxy: wg: new %s; addrs(%v) mtu(%d/%d) peers(%d) / v4(%t) v6(%t)", id, ifaddrs, mtu, calcTunMtu(mtu), len(peers), wgtun.hasV4, wgtun.hasV6)

	return w, nil
}

// ref: github.com/WireGuard/wireguard-go/blob/469159ecf7/tun/netstack/tun.go#L54
func makeWgTun(id string, ifaddrs, allowedaddrs []netip.Prefix, peers map[string]any, dnsm, endpointm *multihost.MH, mtu int) (*wgtun, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	// github.com/tailscale/tailscale/blob/92d3f64e95/net/tstun/mtu.go
	tunmtu := calcTunMtu(mtu)

	s := stack.New(opts)
	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	ep := channel.New(epsize, uint32(tunmtu), "")
	t := &wgtun{
		id:             stripPrefixIfNeeded(id),
		addrs:          ifaddrs,
		allowed:        allowedaddrs,
		peers:          peers,
		remote:         endpointm, // may be nil
		ep:             ep,
		stack:          s,
		events:         make(chan tun.Event, eventssize),
		incomingPacket: make(chan *buffer.View, epsize),
		dns:            dnsm,
		reqbarrier:     core.NewBarrier[[]netip.Addr](wgbarrierttl),
		mtu:            tunmtu,
		status:         TUP,
		preferOffload:  preferOffload(id),
		since:          now(),
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

// Implements Router.
// TODO: use wgtun as a receiver for Stats()
func (w *wgproxy) Stat() (out *x.Stats) {
	out = new(x.Stats)

	if w.status == END {
		return
	}

	cfg, err := w.IpcGet()
	if err != nil || len(cfg) <= 0 {
		log.W("proxy: wg: %s stats: ipcget: %v", w.id, err)
		return
	}

	stat := wg.ReadStats(w.id, cfg)
	if stat == nil { // unlikely
		log.W("proxy: wg: %s stats: readstats: nil", w.id)
		return
	}
	out.Rx = stat.TotalRx()
	out.Tx = stat.TotalTx()
	out.LastOK = stat.LatestRecentHandshake()
	out.Addr = w.IfAddr() // may be empty
	out.ErrRx = w.errRx
	out.ErrTx = w.errTx
	out.LastRx = w.latestRx
	out.LastTx = w.latestTx
	out.Since = w.since
	return out
}

func (w *wgtun) IfAddr() string {
	if len(w.addrs) > 0 {
		return w.addrs[0].String()
	}
	return noaddr
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

// TODO: make wgtun a Router; see Stats()
func (h *wgproxy) Router() x.Router {
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
	names := h.dns.Names()
	for _, hostname := range names {
		s += hostname + ","
	}
	log.D("wg: %s dns hostnames: (in: %v) out: %s", h.id, names, s)
	if len(s) > 0 { // return names, if any
		return strings.TrimRight(s, ",")
	}

	addrs := h.dns.Addrs()
	for _, dns := range addrs {
		if dns.IsUnspecified() || !dns.IsValid() {
			continue
		}
		// may be private, link local, etc
		s += dns.Unmap().String() + ","
	}

	log.D("wg: %s dns ipaddrs: (in: %v) out: %s", h.id, addrs, s)
	if len(s) > 0 { // return ipaddrs, if any
		return strings.TrimRight(s, ",")
	}

	log.W("wg: %s dns: not found (names: %v; addrs: %s)", h.id, names, addrs)
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

	s := TOK // assume err == nil
	if op == "r" && timedout(err) {
		// if status is "up" but writes (op == "w") have not yet happened
		// then reads ("r") are expected to timeout; so ignore them
		if h.latestRx <= 0 {
			s = TNT // writes succeeded; but reads have never
		} else {
			s = TZZ // wirtes and reads have suceeded in the past
		}
	} else if err != nil {
		s = TKO
	}

	if s == TOK {
		if op == "r" {
			h.latestRx = now()
		} else if op == "w" {
			h.latestTx = now()
		}
		writeElapsedMs := h.latestTx - h.latestRx // may be negative
		// if no reads in 20s since last write, then mark as unresponsive
		if writeElapsedMs > 20*1000 {
			s = TNT
		}
	} else if s == TKO {
		if op == "r" {
			h.errRx++
		} else if op == "w" {
			h.errTx++
		}
	}

	h.status = s
}

// now returns the current time in unix millis
func now() int64 {
	return time.Now().UnixMilli()
}

func calcTunMtu(netmtu int) int {
	// uint32(mtu) - 80 is the maximum payload size of a WireGuard packet.
	return max(minmtu6-80, netmtu-80) // 80 is the overhead of the WireGuard header
}

func calcNetMtu(tunmtu int) int {
	// uint32(mtu) - 80 is the maximum payload size of a WireGuard packet.
	return max(minmtu6, tunmtu+80) // 80 is the overhead of the WireGuard header
}

func timedout(err error) bool {
	x, ok := err.(net.Error)
	return ok && x.Timeout()
}

// func Stop(), Fetch(), getDialer() is impl by wgproxy

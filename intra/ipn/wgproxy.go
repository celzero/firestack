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
	"sync/atomic"
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
	id            string                              // id
	cfg           string                              // original config
	addrs         []netip.Prefix                      // interface addresses
	stack         *stack.Stack                        // stack fakes tun device for wg
	ep            *channel.Endpoint                   // reads and writes packets to/from stack
	ingress       chan *buffer.View                   // pipes ep writes to wg
	events        chan tun.Event                      // wg specific tun (interface) events
	finalize      chan struct{}                       // close signal for incomingPacket
	mtu           int                                 // mtu of this interface
	ba            *core.Barrier[[]netip.Addr, string] // request barrier for dns lookups
	once          sync.Once                           // exec fn exactly once
	hasV4, hasV6  bool                                // interface has ipv4/ipv6 routes?
	preferOffload bool                                // UDP GRO/GSO offloads
	since         int64                               // start time in unix millis

	// mutable fields

	peers   *core.Volatile[map[string]device.NoisePublicKey] // peer (remote endpoint) public keys
	dns     *core.Volatile[*multihost.MH]                    // dns resolver for this interface
	allowed *core.Volatile[[]netip.Prefix]                   // allowed ips (peers)
	remote  *core.Volatile[*multihost.MH]                    // peer (remote endpoint) addrs

	status     *core.Volatile[int] // status of this interface
	latestPing atomic.Int64        // last ping time in unix millis
	latestRx   atomic.Int64        // last rx time in unix millis
	latestTx   atomic.Int64        // last tx time in unix millis
	errRx      atomic.Int64        // rx error count
	errTx      atomic.Int64        // tx error count
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
	update(id, txt string) bool
	IpcSet(txt string) error
}

// Dial implements WgProxy
func (h *wgproxy) Dial(network, address string) (c protect.Conn, err error) {
	// ProxyDial resolves address if needed; then dials into all resolved ips.
	return dialers.ProxyDial(h.wgtun, network, address)
}

// Announce implements Proxy.
func (h *wgproxy) Announce(network, local string) (net.PacketConn, error) {
	// todo: dialers.ProxyListenPacket(h.wgtun, network, local)
	return h.wgtun.Announce(network, local)
}

// Accept implements Proxy.
func (h *wgproxy) Accept(network, local string) (net.Listener, error) {
	// todo: dialers.ProxyListen(h.wgtun, network, local)
	return h.wgtun.Accept(network, local)
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

// onProtoChange implements ipn.Proxy
func (w *wgproxy) onProtoChange() (string, bool) {
	_ = w.Refresh() // refresh on proto changes
	// todo: on refresh err, re-add?
	// return w.cfg, true
	return "", false // do not re-add this refreshed wg
}

// Ping implements ipn.Proxy.
// As backpressure, pings are sent once in a 30s period.
func (w *wgproxy) Ping() bool {
	now := now()
	then := w.latestPing.Load()
	neversent := then == 0
	recent := then+30*1000 < now
	if (neversent || !recent) && w.latestPing.CompareAndSwap(then, now) {
		tracked := w.peers.Load()
		tot := len(tracked)
		pinged := 0
		for _, k := range tracked {
			if peer := w.LookupPeer(k); peer != nil {
				pinged++
				peer.SendKeepalive()
			}
		}
		log.D("proxy: wg: %s ping: %d/%d peers", w.id, pinged, tot)
		return pinged > 0
	} else {
		log.VV("proxy: wg: %s ping: skipped; soon? %t / neversent? %t / concurrent %d", w.id, !recent, neversent, then)
	}
	return false
}

// Refresh implements ipn.Proxy
func (w *wgproxy) Refresh() (err error) {
	w.latestPing.Store(0) // reset latest ping time

	n := 0
	if mh := w.dns.Load(); mh != nil {
		n = mh.Refresh()
	}
	nn := 0
	if mh := w.remote.Load(); mh != nil {
		nn = mh.Refresh()
	}
	if err = w.Device.Down(); err != nil {
		log.E("proxy: wg: !refresh(%s): down: len(dns): %d, len(peer): %d, err: %v", w.id, n, nn, err)
		return
	}
	if err = w.Device.Up(); err != nil {
		log.E("proxy: wg: !refresh(%s): up: len(dns): %d, len(peer): %d, err: %v", w.id, n, nn, err)
		return
	}
	// not required since wgconn:NewBind() is namespace aware
	// bindok := bindWgSockets(w.ID(), w.remote.AnyAddr(), w.wgdev, w.ctl)
	log.I("proxy: wg: refresh(%s) done; len(dns): %d, len(peer): %d", w.id, n, nn)
	return
}

func (h *wgproxy) fetch(req *http.Request) (resp *http.Response, err error) {
	stopped := h.status.Load() == END
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
	if w.status.Load() == END {
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
	if dnsh != nil && !dnsh.EqualAddrs(w.dns.Load()) {
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
		w.id, len(w.allowed.Load()), len(allowed), len(w.peers.Load()), len(peers), w.dns.Load().Len(), dnsh.Len(),
		w.remote.Load().Len() /*remote.Load may return nil*/, peersh.Len())
	w.peers.Store(peers) // re-assignment is okay (map entry modification is not)
	w.allowed.Store(allowed)
	w.remote.Store(peersh) // requires refresh
	w.dns.Store(dnsh)      // requires refresh

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

func wgIfConfigOf(id string, txtptr *string) (ifaddrs []netip.Prefix, allowedaddrs []netip.Prefix, peers map[string]device.NoisePublicKey, dnsh, endpointh *multihost.MH, mtu int, err error) {
	txt := *txtptr
	pcfg := strings.Builder{}
	r := bufio.NewScanner(strings.NewReader(txt))
	dnsh = multihost.New(id + "dns")
	endpointh = multihost.New(id + "endpoint")
	peers = make(map[string]device.NoisePublicKey)
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
			var exx error
			var peerkey device.NoisePublicKey
			if exx = peerkey.FromHex(v); exx == nil {
				peers[v] = peerkey
			}
			// peer config: carry over public keys
			log.D("proxy: wg: %s ifconfig: processing key %q, err? %v", id, k, exx)
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

// ref: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L76
func NewWgProxy(id string, ctl protect.Controller, cfg string) (*wgproxy, error) {
	ogcfg := cfg
	ifaddrs, allowedaddrs, peers, dnsh, endpointh, mtu, err := wgIfConfigOf(id, &cfg)
	uapicfg := cfg
	if err != nil {
		log.E("proxy: wg: %s failed to get addrs from config %v", id, err)
		return nil, err
	}

	wgtun, err := makeWgTun(id, ogcfg, ifaddrs, allowedaddrs, peers, dnsh, endpointh, mtu)
	if err != nil {
		log.E("proxy: wg: %s failed to create tun %v", id, err)
		return nil, err
	}

	id = wgtun.id // has stripped prefix FAST, if any

	var wgep wgconn
	if wgtun.preferOffload {
		wgep = wg.NewEndpoint2(id, ctl, endpointh, wgtun.listener)
	} else {
		wgep = wg.NewEndpoint(id, ctl, endpointh, wgtun.listener)
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

	w := &wgproxy{
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
func makeWgTun(id, cfg string, ifaddrs, allowedaddrs []netip.Prefix, peers map[string]device.NoisePublicKey, dnsm, endpointm *multihost.MH, mtu int) (*wgtun, error) {
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
		id:            stripPrefixIfNeeded(id),
		cfg:           cfg,
		addrs:         ifaddrs,
		ep:            ep,
		stack:         s,
		events:        make(chan tun.Event, eventssize),
		ingress:       make(chan *buffer.View, epsize),
		finalize:      make(chan struct{}), // always unbuffered
		allowed:       core.NewVolatile(allowedaddrs),
		dns:           core.NewVolatile(dnsm),
		remote:        core.NewVolatile(endpointm), // may be nil
		peers:         core.NewVolatile(peers),     // its entries must never be modified
		ba:            core.NewBarrier[[]netip.Addr](wgbarrierttl),
		mtu:           tunmtu,
		status:        core.NewVolatile(TUP),
		preferOffload: preferOffload(id),
		since:         now(),
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
	view, ok := <-tun.ingress
	if !ok {
		log.W("wg: %s tun: read closed", tun.id)
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		log.W("wg: %s tun: read(%d): %v", tun.id, n, err)
		return 0, err
	}

	log.VV("wg: %s tun: read(%d)", tun.id, n)
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
		log.VV("wg: %s tun: write: sz(%d); proto %d", tun.id, sz, protoid)
	}

	return len(bufs), nil
}

// WriteNotify is called by channel notifier on readable events
// github.com/google/gvisor/blob/acf460d0d73/pkg/tcpip/link/channel/channel.go#L31
func (tun *wgtun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	sz := view.Size()

	select {
	case <-tun.finalize: // dave.cheney.net/2013/04/30/curious-channels
		log.I("wg: %s tun: write: finalize; dropped pkt; sz(%d)", tun.id, sz)
	default:
		select {
		case <-tun.finalize:
		case tun.ingress <- view: // closed chans panic on send: groups.google.com/g/golang-nuts/c/SDIBFSkDlK4
			log.VV("wg: %s tun: write: notify sz(%d)", tun.id, sz)
		default: // ingress is full and finalize is blocked
			e := tun.status.Load() == END
			log.W("wg: %s tun: write: closed? %t; dropped pkt; sz(%d)", tun.id, e, sz)
		}
	}
}

func (tun *wgtun) Close() error {
	// wgproxy inherits h.status: go.dev/play/p/HeU5EvzAjnv
	if tun.status.Load() == END {
		log.W("proxy: wg: %s tun: already closed?", tun.id)
		return errProxyStopped
	}
	var err error
	tun.once.Do(func() {
		log.D("proxy: wg: %s tun: closing...", tun.id)

		close(tun.finalize)   // unblock all receivers
		tun.status.Store(END) // TODO: move this to wgproxy.Close()?

		tun.stack.RemoveNIC(wgnic)
		// if tun.events != nil {
		// panics; is it closed by device.Device.Close()?
		// close(tun.events) }
		close(tun.ingress)

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
func (w *wgproxy) Stat() (out *x.RouterStats) {
	out = new(x.RouterStats)

	if w.status.Load() == END {
		log.W("proxy: wg: %s stats: stopped", w.id)
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
	out.ErrRx = w.errRx.Load()
	out.ErrTx = w.errTx.Load()
	out.LastRx = w.latestRx.Load()
	out.LastTx = w.latestTx.Load()
	out.Since = w.since

	log.VV("proxy: wg: %s stats: rx: %d, tx: %d, lastok: %d", w.id, out.LastOK, out.Rx, out.Tx)
	return out
}

func (w *wgtun) IfAddr() string {
	ifs := w.addrs
	if len(ifs) > 0 {
		return ifs[0].String()
	}
	return noaddr
}

func (tun *wgtun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *wgtun) BatchSize() int {
	return 1
}

// Dial implements proxy.Dialer and protect.RDialer
func (h *wgtun) Dial(network, address string) (c net.Conn, err error) {
	// wgproxy.Dial -> dialers.ProxyDial -> wgtun.Dial
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s dial: start %s %s", h.id, network, address)

	// DialContext resolves addr if needed; then dialing into all resolved ips.
	if c, err = h.DialContext(context.TODO(), network, address); err != nil {
		h.status.Store(TKO)
	} // else: status updated by h.listener

	log.I("wg: %s dial: end %s %s; err %v", h.id, network, address, err)
	return
}

// Announce implements protect.RDialer
func (h *wgtun) Announce(network, local string) (pc net.PacketConn, err error) {
	// wgproxy.Dial -> dialers.ProxyListenPacket -> protect.AnnounceUDP -> wgtun.Announce
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s announce: start %s %s", h.id, network, local)

	var addr netip.AddrPort
	if addr, err = netip.ParseAddrPort(local); err == nil {
		if pc, err = h.ListenUDPAddrPort(addr); err != nil {
			h.status.Store(TKO)
		} // else: status updated by h.listener
	} // else: expect local to always be ipaddr

	log.I("wg: %s announce: end %s %s; err %v", h.id, network, local, err)
	return
}

func (h *wgtun) Accept(network, local string) (ln net.Listener, err error) {
	// wgproxy.Dial -> dialers.ProxyListen -> protect.AcceptTCP -> wgtun.Accept
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s accept: start %s %s", h.id, network, local)

	var addr netip.AddrPort
	if addr, err = netip.ParseAddrPort(local); err == nil {
		if ln, err = h.ListenTCPAddrPort(addr); err != nil {
			h.status.Store(TKO)
		} // else: status updated by h.listener
	} // else: expect local to always be ipaddr

	log.I("wg: %s accept: end %s %s; err %v", h.id, network, local, err)
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
	return h.status.Load()
}

func (h *wgtun) DNS() string {
	var s string
	// prefer hostnames over IPs:
	// hostnames may resolve to different IPs on different networks;
	// tunnel could use hostnames to implement "refresh"
	dnsm := h.dns.Load()
	if dnsm != nil {
		names := dnsm.Names()
		for _, hostname := range names {
			s += hostname + ","
		}
		log.D("wg: %s dns hostnames (in: %d); out: %s", h.id, names, s)
		if len(s) > 0 { // return names, if any
			return strings.TrimRight(s, ",")
		}

		addrs := dnsm.Addrs()
		for _, dns := range addrs {
			if dns.Addr().IsUnspecified() || !dns.IsValid() {
				continue
			}
			// may be private, link local, etc
			s += dns.Addr().Unmap().String() + ","
		}

		log.D("wg: %s dns ipaddrs (in: %t); out: %s", h.id, addrs, s)
		if len(s) > 0 { // return ipaddrs, if any
			return strings.TrimRight(s, ",")
		}

		log.W("wg: %s dns: not found (names: %v; addrs: %s)", h.id, names, addrs)
	} else { // unlikely as wireguard config is considered invalid if DNS not set
		log.E("wg: %s dns: nil", h.id)
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
	for _, r := range h.allowed.Load() {
		y := r.Contains(ip)
		log.V("wg: %s router: contains: %s in %s? %t", h.id, ip, r, y)
		if y {
			return y
		}
	}

	return false
}

func (h *wgtun) listener(op string, err error) {
	if h.status.Load() == END {
		return
	}

	s := TOK // assume err == nil
	if op == "r" && timedout(err) {
		// if status is "up" but writes (op == "w") have not yet happened
		// then reads ("r") are expected to timeout; so ignore them
		if h.latestRx.Load() <= 0 {
			s = TNT // writes succeeded; but reads have never
		} else {
			s = TZZ // wirtes and reads have succeeded in the past
		}
	} else if err != nil {
		s = TKO
	}

	if s == TOK {
		if op == "r" {
			h.latestRx.Store(now())
		} else if op == "w" {
			h.latestTx.Store(now())
		}
		writeElapsedMs := h.latestTx.Load() - h.latestRx.Load() // may be negative
		// if no reads in 20s since last write, then mark as unresponsive
		if writeElapsedMs > 20*1000 {
			s = TNT
		}
	} else if s == TKO {
		if op == "r" {
			h.errRx.Add(1)
		} else if op == "w" {
			h.errTx.Add(1)
		}
	}

	h.status.Store(s)
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

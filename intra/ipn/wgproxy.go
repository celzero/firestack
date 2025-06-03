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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
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
	"github.com/celzero/firestack/intra/ipn/multihost"
	"github.com/celzero/firestack/intra/ipn/warp"
	"github.com/celzero/firestack/intra/ipn/wg"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
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
	// min mtu for ipv4
	minmtu4 = 576

	pingThresholdMillis          = 5 * 1000 // 5s
	arbitraryWaitForViaHandshake = 5 * time.Second
	markTNTAfterMillis           = 20 * 1000 // TNT after 20s of no rcv after snd

	removeViaOnErrors = false
	resetDeviceOnTNT  = false

	FAST = x.WGFAST

	refreshInterval = 2 * time.Minute

	noviaid = ""
)

type wgifopts struct {
	ifaddrs, allowed []netip.Prefix
	peers            map[string]device.NoisePublicKey
	dns              *multihost.MH
	eps              *multihost.MHMap
	mtu              int
	amnezia          *wg.Amnezia
}

type wgtun struct {
	id  string // id
	cfg string // original config

	addrs         []netip.Prefix    // interface addresses
	stack         *stack.Stack      // stack fakes tun device for wg
	ep            *channel.Endpoint // reads and writes packets to/from stack
	ingress       chan *buffer.View // pipes ep writes to wg
	events        chan tun.Event    // wg specific tun (interface) events
	finalize      chan struct{}     // close signal for incomingPacket
	once          sync.Once         // closer fn; exec exactly once
	preferOffload bool              // UDP GRO/GSO offloads
	since         int64             // start time in unix millis

	px ProxyProvider
	// mutable fields

	via    *core.WeakRef[Proxy]
	viaID  *core.Volatile[string]
	viaUp  *core.Volatile[bool] // using via?
	direct protect.RDialer

	hasV4, hasV6 atomic.Bool // interface has ipv4/ipv6 routes?

	ignoreTUNClose atomic.Bool // set when re-using existing wgtun+wgep but with a new Device

	desiredmtu atomic.Uint32 // desired mtu
	netmtu     atomic.Uint32 // underlay network mtu

	peers   *core.Volatile[map[string]device.NoisePublicKey] // peer (remote endpoint) public keys
	dns     *core.Volatile[*multihost.MH]                    // dns resolver for this interface
	remote  *core.Volatile[*multihost.MHMap]                 // peer (remote endpoint) addrs
	amnezia *core.Volatile[*wg.Amnezia]                      // amnezia/warp config, if any

	rt x.IpTree // route table for this interface

	refreshBa *core.Barrier[bool, string] // 2mins refresh barrier

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
}

type WgProxy interface {
	Proxy
	tun.Device
	update(id, txt string) bool
}

// Handle implements Proxy.
func (h *wgproxy) Handle() uintptr {
	return core.Loc(h)
}

// DialerHandle implements Proxy.
func (h *wgproxy) DialerHandle() uintptr {
	via, up := h.getViaWithStatus()
	if up {
		return via.Handle()
	}
	return core.Loc(h.direct)
}

// Dial implements Proxy.
func (h *wgproxy) Dial(network, address string) (c protect.Conn, err error) {
	// ProxyDial resolves address if needed; then dials into all resolved ips.
	// return dialers.ProxyDial(h.wgtun, network, address)
	return h.wgtun.Dial(network, address)
}

// DialBind implements Proxy.
func (h *wgproxy) DialBind(network, local, remote string) (c protect.Conn, err error) {
	// return dialers.ProxyDialBindh.wgtun, network, local, remote)
	return h.wgtun.DialBind(network, local, remote)
}

// Announce implements Proxy.
func (h *wgproxy) Announce(network, local string) (net.PacketConn, error) {
	return h.wgtun.Announce(network, local)
}

// Accept implements Proxy.
func (h *wgproxy) Accept(network, local string) (net.Listener, error) {
	return h.wgtun.Accept(network, local)
}

// BatchSize implements WgProxy
func (w *wgproxy) BatchSize() int {
	return w.wgtun.BatchSize()
}

// Close implements WgProxy
func (w *wgproxy) Close() error {
	// w.wgtun.Close() called by device.Close() via device.tun.Close()
	w.Device.Close()
	return nil
}

// Stop implements Proxy
func (w *wgproxy) Stop() error {
	log.I("proxy: wg: stopping(%s); status(%d)", w.id, w.status)
	return w.Close()
}

// GetAddr implements x.Proxy
func (h *wgproxy) GetAddr() *x.Gostr {
	dst := h.wgep.RemoteAddr()
	if !dst.IsValid() {
		return x.StrOf(noaddr)
	}
	return x.StrOf(dst.String())
}

// onProtoChange implements Proxy
func (w *wgproxy) OnProtoChange(lp LinkProps) (string, bool) {
	oldmtu := w.netmtu.Swap(uint32(lp.mtu))
	setupReverserIfNeeded(w.id, w.stack, lp.rev)
	log.V("proxy: wg: %s; lp changed; l3: %s, mtu %d=>%d, rev %X",
		w.id, lp.l3, lp.mtu, oldmtu, lp.rev)
	if err := w.Refresh(); err != nil {
		log.W("proxy: wg: %s; lp changed; err: %v", w.id, err)
		// TODO: return w.cfg, true
	}
	return "", false // do not re-add this refreshed wg
}

// Ping implements Proxy
// As backpressure, pings are sent once in a 5s period.
func (w *wgproxy) Ping() bool {
	if w.status.Load() == END {
		log.V("proxy: wg: %s ping: ENDed, status(%d)", w.id, w.status)
		return false
	}

	var viaOK bool
	if via := w.getViaIfDialed(); via != nil {
		viaOK = via.Ping()
	}

	now := now()
	then := w.latestPing.Load()
	neversent := then == 0
	recent := then+pingThresholdMillis < now
	if (neversent || !recent) && w.latestPing.CompareAndSwap(then, now) {
		tracked := w.peers.Load()
		tot := len(tracked)
		pinged := 0
		// or: w.Device.SendKeepalivesToPeersWithCurrentKeypair()
		for _, k := range tracked {
			if peer := w.LookupPeer(k); peer != nil {
				pinged++
				// keepalive are empty packets but always padded to 16 bytes
				// github.com/bepass-org/warp-plus/blob/12269c2761/wireguard/device/noise-protocol.go#L67
				// github.com/wireguard/wireguard-go/blob/12269c2761/wireguard/device/send.go#L543
				// WireGuard: Next Generation Kernel Network Tunnel, rev e2da747, section 6.5
				peer.SendKeepalive()
			}
		}
		log.D("proxy: wg: %s (%s) ping: %d/%d peers; via OK? %t", w.id, w.viaStatus(), pinged, tot, viaOK)
		return pinged > 0
	} else {
		log.VV("proxy: wg: %s (%s) ping: skipped; soon? %t / neversent? %t / concurrent %d; via OK? %t",
			w.id, w.viaStatus(), !recent, neversent, then, viaOK)
	}
	return false
}

func waitForViaHandshake() {
	time.Sleep(arbitraryWaitForViaHandshake)
}

// onNotOK implements Proxy.
func (w *wgproxy) onNotOK() (didRefresh, allok bool) {
	var didPing, viaDidRefresh, viaOK bool

	if via := w.getViaIfDialed(); via != nil {
		viaDidRefresh, viaOK = via.onNotOK()
	}

	var err error
	if viaDidRefresh {
		waitForViaHandshake() // wait for via to be OK
		err = w.Refresh()
		didRefresh = true
		allok = err == nil
	} else {
		allok, err = w.refreshBa.DoIt(w.id, func() (bool, error) {
			rerr := w.Refresh()
			didRefresh = true
			return rerr == nil, rerr
		})
	}
	if !didRefresh { // attempt Ping if refresh skipped by the barrier
		allok = allok && w.Ping() // ping / sendkeepalive is async
		didPing = true
	}
	loged(err)("proxy: wg: %s (%s); onNotOK: refresh? %t+%t; ping? %t; ok? %t+%t; err? %v",
		w.id, w.viaStatus(), viaDidRefresh, didRefresh, didPing, viaOK, allok, err)
	return
}

// Refresh implements Proxy.
func (w *wgproxy) Refresh() (err error) {
	// todo: Refresh may be called by hop-related changes which may result in one Refresh calls too many.
	if w.status.Load() == END {
		log.W("proxy: wg: %s (%s) refresh failed; end status(%d)", w.id, w.viaStatus(), w.status)
		return errProxyStopped
	}

	resetDevice := resetDeviceOnTNT && status == TNT

	w.latestPing.Store(0) // reset latest ping time

	n := w.dns.Load().Refresh()
	nn := w.remote.Load().Refresh()

	via := w.getVia()
	viaOK, didWait := false, false
	if via != nil {
		var viaDidRefresh bool
		if viaDidRefresh, viaOK = via.onNotOK(); viaDidRefresh {
			waitForViaHandshake()
			didWait = true
		}
	}

	if err = w.resetMtu(via); err == nil {
		err = w.Device.Down()
		resetDevice = resetDevice && w.wgtun.ignoreTUNClose.CompareAndSwap(false, true)
		if resetDevice && err == nil {
			var newdev *device.Device
			const useExistingCfg = ""
			if newdev, err = newdevice(w.wgtun, w.wgep, useExistingCfg); err == nil {
				w.Device.Close()  // will end up calling wgtun.Close() which hopefully is ignored
				w.Device = newdev // TODO: core.Volatile[device.Device]
			} // newdevice calls w.Device.Up() internally
		} else if err == nil {
			err = w.Device.Up()
		}
	}
	// not required since wgconn:NewBind() is namespace aware
	// bindok := bindWgSockets(w.ID(), w.remote.AnyAddr(), w.wgdev, w.ctl)
	logei(err)("proxy: wg: %s (%s): refresh done; len(dns): %d, len(peer): %d; viaOK? %t, didWait? %t / reset? %t; err? %v",
		w.id, w.viaStatus(), n, nn, viaOK, didWait, resetDevice, err)
	return
}

func (h *wgproxy) Dialer() protect.RDialer {
	return h
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
	const reused = true // can update in-place; reuse existing tunnel
	const anew = false  // cannot update in-place; create new tunnel
	if w.status.Load() == END {
		log.W("proxy: wg: update(%s<>%s): END; status(%d)", id, w.id, w.status)
		return anew
	}

	incomingPrefersOffload := preferOffload(id)
	if incomingPrefersOffload != w.preferOffload {
		log.W("proxy: wg: update(%s): failed; preferOffload() %t != %t", id, incomingPrefersOffload, w.preferOffload)
		return anew
	}

	// str copy: go.dev/play/p/eO814kGGNtO
	cptxt := txt
	opts, err := wgIfConfigOf(w.id, &cptxt)
	if err != nil {
		log.W("proxy: wg: update(%s): err: %v", w.id, err)
		return anew
	}

	if err := w.setRoutes(opts.ifaddrs); err != nil {
		log.W("proxy: wg: update(%s): failed; setRoutes: %v", w.id, err)
		return anew
	}

	if settings.Debug {
		if !w.amnezia.Load().Same(opts.amnezia) {
			log.D("proxy: wg: update(%s): failed; amnezia %v != %v",
				w.id, opts.amnezia, w.amnezia.Load())
		}
		if opts.dns != nil && !opts.dns.EqualAddrs(w.dns.Load()) {
			log.D("proxy: wg: update(%s): failed; new/mismatched dns", w.id)
		} // nb: client code MUST re-add wg DNS, not our responsibility
	}

	maybeNewMtu := calcTunMtu(opts.mtu) // only for logging

	// reusing existing tunnel (interface config unchanged)
	// but peer config may have changed!
	log.I("proxy: wg: update: %s (%s): reuse; mtu: %d=>%d, allowed: %d=>%d; peers: %d=>%d; dns: %d=>%d; endpoint: %d=>%d",
		w.id, w.viaStatus(), w.ep.MTU(), maybeNewMtu, w.rt.Len(), len(opts.allowed), len(w.peers.Load()), len(opts.peers), w.dns.Load().Len(), opts.dns.Len(),
		w.remote.Load().Len() /*remote.Load may return nil*/, opts.eps.Len())

	w.peers.Store(opts.peers) // re-assignment is okay (map entry modification is not)
	w.allowedIPs(opts.allowed)
	w.remote.Store(opts.eps)             // requires refresh (wg.Conn:ParseEndpoint must be re-called)
	w.dns.Store(opts.dns)                // requires refresh (client must also re-add via intra.AddDNSProxy)
	w.desiredmtu.Store(uint32(opts.mtu)) // requires reset; [NOMTU, MAXMTU)
	w.amnezia.Store(opts.amnezia)
	w.resetMtu(w.getVia())

	ipcerr := w.IpcSet(cptxt)
	if ipcerr != nil {
		log.W("proxy: updating wg(%s) ipcset; err %v", id, ipcerr)
		return anew
	}

	return reused
}

func (w *wgtun) allowedIPs(allowed []netip.Prefix) {
	w.rt.Clear()
	for _, ipnet := range allowed {
		w.rt.Set(x.StrOf(ipnet.String()), x.StrOf(w.id))
	}
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

func wgIfConfigOf(id string, txtptr *string) (opts wgifopts, err error) {
	txt := *txtptr
	pcfg := strings.Builder{}
	r := bufio.NewScanner(strings.NewReader(txt))
	opts.dns = multihost.New(id + "dns")
	opts.eps = multihost.NewMap(id + "endpoint")
	opts.peers = make(map[string]device.NoisePublicKey)
	opts.amnezia = wg.NewAmnezia(id)
	opts.mtu = MAXMTU // auto

	var currentPeer *multihost.MH
	for r.Scan() {
		line := r.Text()
		if len(line) <= 0 {
			// Blank line means terminate operation.
			if (len(opts.ifaddrs) <= 0) || (opts.dns.Len() <= 0) || (opts.mtu <= 0) {
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
			if err = loadIPNets(&opts.ifaddrs, v); err != nil {
				return
			}
		case "dns": // may exist more than once: github.com/celzero/rethink-app/issues/1298
			n := loadMH(opts.dns, v)
			log.D("proxy: wg: %s ifconfig: dns(%d) %s", id, n, v)
		case "mtu":
			maxxed := false
			if len(v) <= 0 || v == AUTOMTU || v == AUTOMTU2 {
				opts.mtu = MAXMTU
				maxxed = true
			} else if opts.mtu, err = strconv.Atoi(v); err != nil {
				return
			}
			if opts.mtu < NOMTU { // negative
				opts.mtu = MAXMTU
				maxxed = true
			}
			log.D("proxy: wg: %s ifconfig: mtu %s => %d; maxxed? %t",
				id, v, opts.mtu, maxxed)
		case "allowed_ip": // may exist more than once
			if err = loadIPNets(&opts.allowed, v); err != nil {
				return
			}
			// peer config: carry over allowed_ips
			log.D("proxy: wg: %s ifconfig: skipping key %q", id, k)
			pcfg.WriteString(line + "\n")
		case "endpoint": // may exist more than once
			// TODO: endpoint could be v4 or v6 or a hostname
			n := 0
			if id == RpnWg { // warp
				v4, v6, err := warp.WarpEndpoints()
				if err == nil {
					warpipcsv := v4.String() + "," + v6.String()
					n = loadMH(currentPeer, warpipcsv)
				}
				logev(err)("proxy: wg: %s v4 %s, v6 %s; added? %d; err? %v",
					id, v4, v6, n, err)
			}
			n += loadMH(currentPeer, v) // append more endpoints
			log.D("proxy: wg: %s ifconfig: endpoints(%d) %s", id, n, v)

			// peer config: carry over endpoints
			log.D("proxy: wg: %s ifconfig: skipping key %q", id, k)
			pcfg.WriteString(line + "\n")
		case "public_key":
			var exx error
			var peerkey device.NoisePublicKey
			if exx = peerkey.FromHex(v); exx == nil {
				opts.peers[v] = peerkey
			}
			// peer config: carry over public keys
			log.D("proxy: wg: %s ifconfig: processing key %q, err? %v", id, k, exx)
			pcfg.WriteString(line + "\n")
			finalizeMH(opts.eps, currentPeer)
			if len(v) > 8 {
				v = v[:8]
			}
			// a public_key line points to a transition to a new peer
			// github.com/WireGuard/wireguard-go/blob/12269c2761/device/uapi.go#L295
			currentPeer = multihost.New(id + ":" + v) // next peer
		case "client_id":
			// only for warp: blog.cloudflare.com/warp-technical-challenges
			// When we begin a WireGuard session we include our clientid field
			// which is provided by our authentication server which has to be
			// communicated with to begin a WARP session.
			// Though the open source Cloudflare WARP boring-tun impl does not do so:
			// github.com/cloudflare/boringtun/blob/64a2fc7c63/boringtun/src/noise/handshake.rs#L734
			if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) == 3 {
				// github.com/WireGuard/wireguard-go/blob/12269c2761/device/send.go#L456
				// github.com/WireGuard/wireguard-go/blob/12269c2761/device/noise-protocol.go#L56
				h1 := append([]byte{device.MessageInitiationType}, b...)
				h2 := append([]byte{device.MessageResponseType}, b...)
				h3 := append([]byte{device.MessageCookieReplyType}, b...)
				h4 := append([]byte{device.MessageTransportType}, b...)
				// overwrite the 3 reserved bytes on all packets
				// github.com/bepass-org/warp-plus/blob/19ac233cc6/wireguard/device/receive.go#L138
				opts.amnezia.H1 = binary.LittleEndian.Uint32(h1)
				opts.amnezia.H2 = binary.LittleEndian.Uint32(h2)
				opts.amnezia.H3 = binary.LittleEndian.Uint32(h3)
				opts.amnezia.H4 = binary.LittleEndian.Uint32(h4)
				log.D("proxy: wg: %s ifconfig: clientid(%d) %v", id, len(b), b)
			} else {
				log.W("proxy: wg: %s ifconfig: clientid(%v) %d == 3?; err: %v",
					id, v, len(b), err)
			}
		case "jc":
			// github.com/amnezia-vpn/amneziawg-go/blob/2e3f7d122c/device/uapi.go#L286
			jc, _ := strconv.Atoi(v)
			opts.amnezia.Jc = uint16(jc)
		case "jmin":
			jmin, _ := strconv.Atoi(v)
			opts.amnezia.Jmin = uint16(jmin)
		case "jmax":
			jmax, _ := strconv.Atoi(v)
			opts.amnezia.Jmax = uint16(jmax)
		case "s1":
			s1, _ := strconv.Atoi(v)
			opts.amnezia.S1 = uint16(s1)
		case "s2":
			s2, _ := strconv.Atoi(v)
			opts.amnezia.S2 = uint16(s2)
		case "h1":
			h1, _ := strconv.ParseUint(v, 10, 32)
			opts.amnezia.H1 = uint32(h1)
		case "h2":
			h2, _ := strconv.ParseUint(v, 10, 32)
			opts.amnezia.H2 = uint32(h2)
		case "h3":
			h3, _ := strconv.ParseUint(v, 10, 32)
			opts.amnezia.H3 = uint32(h3)
		case "h4":
			h4, _ := strconv.ParseUint(v, 10, 32)
			opts.amnezia.H4 = uint32(h4)
		default:
			log.D("proxy: wg: %s ifconfig: skipping key %q", id, k)
			pcfg.WriteString(line + "\n")
		}
	}
	finalizeMH(opts.eps, currentPeer)
	*txtptr = pcfg.String()
	if err == nil && len(opts.ifaddrs) <= 0 || opts.dns.Len() <= 0 || opts.mtu <= NOMTU {
		err = errProxyConfig
	}
	loged(err)("proxy: wg: %s; addr: %d, dns: %d, mtu: %d, eps: %d; amnezia: %s",
		id, len(opts.ifaddrs), opts.dns.Len(), opts.mtu, opts.eps.Len(), opts.amnezia)
	return
}

func finalizeMH(m *multihost.MHMap, currentPeer *multihost.MH) bool {
	if currentPeer == nil {
		return false
	}
	return m.Put(currentPeer)
}

func loadMH(mh *multihost.MH, v string) int {
	if mh == nil || len(v) <= 0 {
		return 0
	}
	vv := strings.Split(v, ",")
	return mh.Add(vv) // vv may be host:port, ip:port, host, or ip
}

func loadIPNets(out *[]netip.Prefix, v string) (err error) {
	var ip netip.Addr
	// may be a csv: "172.1.0.2/32, 2000:db8::2/128"
	for str := range strings.SplitSeq(v, ",") {
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
func NewWgProxy(id string, ctl protect.Controller, px ProxyProvider, lp LinkProps, cfg string) (*wgproxy, error) {
	ogcfg := cfg
	opts, err := wgIfConfigOf(id, &cfg)
	uapicfg := cfg
	if err != nil {
		log.E("proxy: wg: %s failure getting opts from config %v", id, err)
		return nil, err
	}

	wgtun, err := makeWgTun(id, ogcfg, ctl, px, lp, opts)
	if err != nil {
		log.E("proxy: wg: %s failed to create tun %v", id, err)
		return nil, err
	}

	id = wgtun.id // has stripped prefixes (like FAST), if any

	var wgep wgconn
	if wgtun.preferOffload {
		// todo: use wgtun.serve fn instead of ctl
		// todo: wgtun.remote instead of opts.eps
		// todo: amnezia/warp config
		wgep = wg.NewEndpoint2(id, ctl, opts.eps, wgtun.listener)
	} else {
		wgep = wg.NewEndpoint(id, wgtun.serve, wgtun.remote, wgtun.listener, wgtun.amnezia)
	}

	wgdev, err := newdevice(wgtun, wgep, uapicfg)
	if err != nil {
		return nil, err
	}

	w := &wgproxy{
		wgtun, // stack
		wgdev, // device
		wgep,  // endpoint
	}

	log.D("proxy: wg: new %s; addrs(%v) mtu(%d/%d) peers(%d) / v4(%t) v6(%t)",
		id, opts.ifaddrs, opts.mtu, w.ep.MTU(), len(opts.peers), wgtun.hasV4.Load(), wgtun.hasV6.Load())

	return w, nil
}

func newdevice(wgtun *wgtun, wgep wgconn, uapicfg string) (*device.Device, error) {
	wgdev := device.NewDevice(wgtun, wgep, wglogger(wgtun.id))

	if len(uapicfg) <= 0 {
		uapicfg = wgtun.cfg // copy
		if _, err := wgIfConfigOf(wgtun.id, &uapicfg); err != nil {
			return nil, err
		}
	}

	err := wgdev.IpcSet(uapicfg)
	if err != nil {
		defer wgdev.Close()
		log.E("proxy: wg: %s failed to ipc-set %v", wgtun.id, err)
		return nil, err
	}

	// github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L99
	wgdev.DisableSomeRoamingForBrokenMobileSemantics()

	err = wgdev.Up() // needed? tun.EventUp is already queued by makeWgTun()
	if err != nil {
		defer wgdev.Close()
		log.E("proxy: wg: %s failed init %v", wgtun.id, err)
		return nil, err
	}
	return wgdev, nil
}

func setupReverserIfNeeded(id string, s *stack.Stack, rev netstack.GConnHandler) {
	if rev != nil && settings.ExperimentalWireGuard.Load() && settings.EndpointIndependentFiltering.Load() {
		// inbound (aka reverse outbound)
		netstack.OutboundTCP(id, s, rev.TCP())
		netstack.OutboundUDP(id, s, rev.UDP())
		log.I("proxy: wg: %s rev @ %X enabled", id, rev)
		return
	} // do not use reverser
	log.W("proxy: wg: %s remove rev %X", id, rev)
	netstack.OutboundTCP(id, s, nil) // unset
	netstack.OutboundUDP(id, s, nil) // unset
}

func (w *wgtun) swapVia(new Proxy) (old Proxy) {
	return swapVia(w.id, new, w.viaID, w.via)
}

func (w *wgtun) viafor() *Proxy {
	return viafor(w.id, w.viaID.Load(), w.px)
}

func (w *wgtun) getVia() (v Proxy) {
	return w.via.Load()
}

func (w *wgtun) getViaWithStatus() (v Proxy, up bool) {
	up = w.viaUp.Load()
	v = w.getVia()
	return
}

func (w *wgtun) getViaIfDialed() Proxy {
	if v, up := w.getViaWithStatus(); up {
		return v
	}
	return nil
}

func (w *wgtun) viaStatus() (s string) {
	v, up := w.getViaWithStatus()
	if vid := idstr(v); len(vid) > 0 {
		s += vid
		if up {
			s += "/up"
		} else {
			s += "/down"
		}
	} else {
		if vid = w.viaID.Load(); len(vid) > 0 {
			s += vid + "/mia"
		} else {
			s += "novia/zz"
		}
	}
	return s
}

// ref: github.com/WireGuard/wireguard-go/blob/469159ecf7/tun/netstack/tun.go#L54
func makeWgTun(id, cfg string, ctl protect.Controller, px ProxyProvider, lp LinkProps, ifopts wgifopts) (*wgtun, error) {
	ctx := context.TODO()

	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}

	minmtu := minmtu6 // ip6 or ip6 or ip4+ip6
	if lp.l3 == settings.IP4 {
		minmtu = minmtu4 // ip4
	}

	tunMtu := reconcileMtu(lp.mtu, ifopts.mtu, minmtu)
	if tunMtu <= NOMTU {
		return nil, errNoMtu
	}

	s := stack.New(opts)
	ep := channel.New(epsize, uint32(tunMtu), "")
	netstack.SetNetstackOpts(s)
	setupReverserIfNeeded(id, s, lp.rev) // rev may be nil

	t := &wgtun{
		id:            stripPrefixIfNeeded(id),
		cfg:           cfg,
		addrs:         ifopts.ifaddrs,
		ep:            ep,
		stack:         s,
		events:        make(chan tun.Event, eventssize),
		ingress:       make(chan *buffer.View, epsize),
		finalize:      make(chan struct{}), // always unbuffered
		direct:        protect.MakeNsRDial(id, ctx, ctl),
		px:            px,
		viaID:         core.NewZeroVolatile[string](),
		viaUp:         core.NewZeroVolatile[bool](),
		dns:           core.NewVolatile(ifopts.dns),
		remote:        core.NewVolatile(ifopts.eps),   // may be nil
		peers:         core.NewVolatile(ifopts.peers), // its entries must never be modified
		rt:            x.NewIpTree(),                  // must be set to allowedaddrs
		amnezia:       core.NewVolatile(ifopts.amnezia),
		status:        core.NewVolatile(TUP),
		preferOffload: preferOffload(id),
		refreshBa:     core.NewBarrier[bool](refreshInterval),
		since:         now(),
	}
	t.desiredmtu.Store(uint32(ifopts.mtu))
	t.netmtu.Store(uint32(lp.mtu))
	t.allowedIPs(ifopts.allowed)

	if viaref, verr := core.NewWeakRef(t.viafor, viaok); verr != nil {
		return nil, fmt.Errorf("wg: %s create tun (via ref): %v", t.id, verr)
	} else {
		t.via = viaref
	}

	// see WriteNotify below
	ep.AddNotify(t)

	if err := s.CreateNIC(wgnic, ep); err != nil {
		return nil, fmt.Errorf("wg: %s create nic: %v", t.id, err)
	}

	if settings.ExperimentalWireGuard.Load() {
		// github.com/xjasonlyu/tun2socks/blob/31468620e/core/stack.go#L80
		_ = s.SetSpoofing(wgnic, true)
		// github.com/tailscale/tailscale/blob/c4d0237e5c/wgengine/netstack/netstack.go#L345-L350
		_ = s.SetPromiscuousMode(wgnic, true)
	}

	if err := t.setRoutes(ifopts.ifaddrs); err != nil {
		return nil, err
	}

	// commence the wireguard state machine the second Device is created
	t.events <- tun.EventUp

	if4, if6 := netstack.StackAddrs(s, wgnic)
	log.I("proxy: wg: %s tun: created; dns[%s]; dst[%s]; mtu[%d]; ifaddrs[%v / %v]; amnezia[%t]",
		t.id, ifopts.dns, ifopts.eps, tunMtu, if4, if6, ifopts.amnezia.Set())

	return t, nil
}

func (t *wgtun) setRoutes(ifaddrs []netip.Prefix) error {
	processed := make(map[netip.Prefix]bool)
	for _, ipnet := range ifaddrs {
		ip := ipnet.Addr()
		if processed[ipnet] {
			log.W("proxy: wg: %s skipping duplicate ip %v for ifaddr %v",
				t.id, ip, ipnet)
			continue
		}
		processed[ipnet] = true

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
		if err := t.stack.AddProtocolAddress(wgnic, protoaddr, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("wg: %s add addr(%v): %v", t.id, ip, err)
		}
		t.hasV4.Store(t.hasV4.Load() || ip.Is4())
		t.hasV6.Store(t.hasV6.Load() || ip.Is6())
		log.D("proxy: wg: %s added ifaddr(%v)", t.id, ap)
	}
	if t.hasV4.Load() {
		t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: wgnic})
	}
	if t.hasV6.Load() {
		t.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: wgnic})
	}
	return nil
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
		log.W("wg: %s (%s) tun: read closed", tun.id, tun.viaStatus())
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		log.W("wg: %s (%s) tun: read(%d): %v",
			tun.id, tun.viaStatus(), n, err)
		return 0, err
	}

	log.VV("wg: %s (%s) tun: read(%d)", tun.id, tun.viaStatus(), n)
	sizes[0] = n
	return 1, nil
}

func (tun *wgtun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			log.D("wg: %s (%s) tun: write: empty packet", tun.id, tun.viaStatus())
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
			log.W("wg: %s (%s) tun: write: unknown proto %d; discard %d",
				tun.id, tun.viaStatus(), protoid, sz)
			return 0, syscall.EAFNOSUPPORT
		}
		log.VV("wg: %s (%s) tun: write: sz(%d); proto %d",
			tun.id, tun.viaStatus(), sz, protoid)
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
		log.I("wg: %s (%s) tun: write: finalize; dropped pkt; sz(%d)",
			tun.id, tun.viaStatus(), sz)
	default:
		select {
		case <-tun.finalize:
		case tun.ingress <- view: // closed chans panic on send: groups.google.com/g/golang-nuts/c/SDIBFSkDlK4
			log.VV("wg: %s (%s) tun: write: notify sz(%d)",
				tun.id, tun.viaStatus(), sz)
		default: // ingress is full and finalize is blocked
			e := tun.status.Load()
			log.W("wg: %s (%s) tun: write: closed? %t; dropped pkt; sz(%d)",
				tun.id, tun.viaStatus(), e, sz)
		}
	}
}

func (tun *wgtun) Close() error {
	// wgproxy inherits h.status: go.dev/play/p/HeU5EvzAjnv
	if tun.status.Load() == END {
		log.W("wg: %s (%s) tun: already closed?", tun.id, tun.viaStatus())
		return errProxyStopped
	}
	if tun.ignoreTUNClose.CompareAndSwap(true, false) {
		log.I("wg: %s (%s) tun: ignore close this once", tun.id, tun.viaStatus())
		return nil // ignore
	}

	var err error
	tun.once.Do(func() {
		log.D("wg: %s (%s) tun: closing...", tun.id, tun.viaStatus())

		close(tun.finalize)   // unblock all receivers
		tun.status.Store(END) // TODO: move this to wgproxy.Close()?

		tun.stack.RemoveNIC(wgnic)
		// if tun.events != nil {
		// panics; is it closed by device.Device.Close()?
		// close(tun.events) }
		close(tun.ingress)

		tun.viaID.Store(noviaid) // via is nil
		tun.viaUp.Store(false)

		// github.com/tailscale/tailscale/blob/836f932e/wgengine/netstack/netstack.go#L223

		// stack closes the endpoint, too via nic.go#remove?
		// tun.ep.Close()
		// destroy waits for the stack to close
		tun.stack.Destroy()
		log.I("wg: %s tun: closed", tun.id)
	})
	return err
}

// Implements Router.
// TODO: use wgtun as a receiver for Stats()
// Never returns nil.
func (w *wgproxy) Stat() (out *x.RouterStats) {
	out = new(x.RouterStats)

	if w.status.Load() == END {
		log.W("proxy: wg: %s (%s) stats: stopped", w.id, w.viaStatus())
		return // zz
	}

	stat := wg.ReadStats(w.id, w.Handle(), w.IpcGet)
	if stat == nil { // unlikely
		log.V("proxy: wg: %s (%s) stats: readstats: nil", w.id, w.viaStatus())
		return // zz
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

	log.VV("proxy: wg: %s stats: rx: %d, tx: %d, lastok: %s",
		w.id, out.Rx, out.Tx, core.FmtUnixMillisAsPeriod(out.LastOK))
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
	return calcNetMtu(int(tun.ep.MTU())), nil
}

func (tun *wgtun) BatchSize() int {
	return 1
}

// Dial implements proxy.Dialer and protect.RDialer
func (h *wgtun) Dial(network, address string) (c net.Conn, err error) {
	// wgproxy.Dial => dialers.ProxyDial => wgtun.Dial
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s dial: start %s %s %s",
		h.id, network, address, h.viaStatus())

	// DialContext resolves addr if needed; then dialing into all resolved ips.
	if c, err = h.DialContext(context.TODO(), network, address); err != nil {
		h.status.Store(TKO)
	} // else: status updated by h.listener

	log.I("wg: %s dial: end %s %s %s; err %v",
		h.id, network, address, h.viaStatus(), err)
	return
}

// DialBind implements proxy.Dialer and protect.RDialer
func (h *wgtun) DialBind(network, local, remote string) (c net.Conn, err error) {
	// wgproxy.DialBind => wgtun.Dial
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s dialbind: start %s %s=>%s %s",
		h.id, network, local, remote, h.viaStatus())

	// DialContext resolves addr if needed; then dialing into all resolved ips.
	if c, err = h.DialContext(context.TODO(), network, remote); err != nil {
		h.status.Store(TKO)
	} // else: status updated by h.listener

	log.I("wg: %s dial: end %s %s %s; err %v",
		h.id, network, remote, h.viaStatus(), err)
	return
}

// Announce implements protect.RDialer
func (h *wgtun) Announce(network, local string) (pc net.PacketConn, err error) {
	// wgproxy.Dial => dialers.ProxyListenPacket => protect.AnnounceUDP => wgtun.Announce
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s announce: start %s %s %s",
		h.id, network, local, h.viaStatus())

	var addr netip.AddrPort
	if addr, err = netip.ParseAddrPort(local); err == nil {
		if pc, err = h.ListenUDPAddrPort(addr); err != nil {
			h.status.Store(TKO)
		} // else: status updated by h.listener
	} // else: expect local to always be ipaddr

	log.I("wg: %s announce: end %s %s %s; err %v",
		h.id, network, local, h.viaStatus(), err)
	return
}

// Accept implements protect.RDialer
func (h *wgtun) Accept(network, local string) (ln net.Listener, err error) {
	// wgproxy.Dial => dialers.ProxyListen => protect.AcceptTCP => wgtun.Accept
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s accept: start %s %s %s",
		h.id, network, local, h.viaStatus())

	var addr netip.AddrPort
	if addr, err = netip.ParseAddrPort(local); err == nil {
		if ln, err = h.ListenTCPAddrPort(addr); err != nil {
			h.status.Store(TKO)
		} // else: status updated by h.listener
	} // else: expect local to always be ipaddr

	log.I("wg: %s accept: end %s %s %s; err %v",
		h.id, network, local, h.viaStatus(), err)
	return
}

// Probe implements protect.RDialer
func (h *wgtun) Probe(network, local string) (pc net.PacketConn, err error) {
	// wgproxy.Dial => dialers.ProxyListen => protect.AcceptTCP => wgtun.Accept
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	log.D("wg: %s probe: start %s %s %s",
		h.id, network, local, h.viaStatus())

	var addr netip.AddrPort
	if addr, err = netip.ParseAddrPort(local); err == nil {
		if pc, err = h.ListenUDPAddrPort(addr); err != nil {
			h.status.Store(TKO)
		} // else: status updated by h.listener
	} // else: expect local to always be ipaddr

	log.I("wg: %s probe: end %s %s %s; err %v",
		h.id, network, local, h.viaStatus(), err)
	return
}

// ID implements x.Proxy.
func (h *wgtun) ID() *x.Gostr {
	return x.StrOf(h.id)
}

// Type implements x.Proxy.
func (h *wgtun) Type() *x.Gostr {
	return x.StrOf(WG)
}

// Router implements Proxy.
// TODO: make wgtun a Router; see Stats()
func (h *wgproxy) Router() x.Router {
	return h
}

// Reaches implements x.Router.
// TODO: make wgtun a Router; see Stats()
func (h *wgproxy) Reaches(hostportOrIPPortCsv *x.Gostr) bool {
	return Reaches(h, hostportOrIPPortCsv.V())
}

// Hop implements Proxy.
func (h *wgproxy) Hop(via Proxy, dryrun bool) (err error) {
	var old Proxy

	defer func() {
		if dryrun {
			return
		}

		log.I("wg: %s hop: old(%s) => new(%s); err? %v",
			h.id, idhandle(old), idhandle(via), err)

		if Same(old, via) {
			return
		}
		if err == nil {
			go h.Refresh() // reconnect
		}
	}()

	if via == nil {
		if !dryrun {
			old = h.swapVia(nil)
			// undo MTU enforced due to any prior hops
			if old != nil {
				err = h.resetMtu(nil)
			}
			log.I("wg: %s hop: %s removed; mtu reset err? %v",
				h.id, idhandle(old), err)
		}
		return nil
	} else if Same(h, via) {
		return errHopSelf
	}

	if via.Status() == END {
		return errProxyStopped
	}

	if !isWG(idstr(via)) { // for now, only wg can hop another wg
		return errHopWireGuard
	}

	if err := hopCanRoute(h, via); err != nil {
		return err
	}

	// mtu needed to tunnel this wg
	if err := h.maybeResetMtu(via, dryrun); err != nil {
		return err // could not set mtu
	}

	if !dryrun {
		old = h.swapVia(via)
	}
	return nil
}

// Via implements x.Router.
func (h *wgproxy) Via() (x.Proxy, error) {
	if v, up := h.getViaWithStatus(); v == nil {
		return nil, errNoHop
	} else if !up {
		return nil, errHopNotConnected
	} else {
		return v, nil
	}
}

// Stats implements Proxy.
func (h *wgtun) Status() int {
	return h.status.Load()
}

// DNS implements x.Proxy.
func (h *wgtun) DNS() *x.Gostr {
	return x.StrOf(h.dnsResolvers())
}

func (h *wgtun) dnsResolvers() string {
	var s string
	// prefer hostnames over IPs:
	// hostnames may resolve to different IPs on different networks;
	// tunnel could use hostnames to implement "refresh"
	dnsm := h.dns.Load()
	vid := h.viaStatus()
	if dnsm != nil {
		names := dnsm.Names()
		for _, hostname := range names {
			s += hostname + ","
		}
		log.D("wg: %s (%s) dns hostnames (in: %d); out: %s",
			h.id, vid, names, s)
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

		log.D("wg: %s (%s) dns ipaddrs (in: %v); out: %s",
			h.id, vid, addrs, s)
		if len(s) > 0 { // return ipaddrs, if any
			return strings.TrimRight(s, ",")
		}

		log.W("wg: %s (%s) dns: not found (names: %v; addrs: %s)",
			h.id, vid, names, addrs)
	} else { // unlikely as wireguard config is considered invalid if DNS not set
		log.E("wg: %s (%s) dns: nil", h.id, vid)
	}
	return "" // nodns
}

// Implements x.Router.
func (h *wgtun) IP4() bool { return h.hasV4.Load() }
func (h *wgtun) IP6() bool { return h.hasV6.Load() }

// Contains implements x.Router.
func (h *wgtun) Contains(ippOrCidr *x.Gostr) bool {
	y, err := h.rt.HasAny(ippOrCidr)
	logev(err)("wg: %s (%s) router: %s contains? %t; err? %v",
		h.id, h.viaStatus(), ippOrCidr, y, err)
	return y
}

func (h *wgtun) serve(network, local string) (pc net.PacketConn, err error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	// todo: dial into both direct & via if via cannot handle all routes?
	who := h.id
	var v Proxy // may be nil
	hasvia, usingvia := false, false
	if hasvia = usevia(h.viaID); hasvia {
		if v, usingvia = h.via.Get(); v != nil && usingvia {
			// TODO: use Dial if announce fails to "port-forward" on via
			pc, err = v.Announce(network, local)
		} else {
			usingvia = false
			err = errNoHop
			// wgproxy.Refresh() is not needed since serve is called
			// at the time of wgproxy.Device.Up() anyway.
			if removeViaOnErrors {
				// todo: ideally, must call h.Hop(nil) here
				h.swapVia(nil) // stale; unset
			}
			log.W("wg: %s via(%s) failing...", h.id, idhandle(v))
		}
	} else { // dial direct
		pc, err = h.direct.Announce(network, local)
	}
	h.viaUp.Store(usingvia)
	defer localDialStatus(h.status, err)

	logei(err)("wg: %s serve: %s (id? %s / via? %s / usingVia? %t); err? %v",
		h.id, local, who, idstr(v), usingvia, err)
	return
}

func (h *wgtun) listener(op wg.PktDir, err error) {
	if h.status.Load() == END {
		return
	}

	s := TOK // assume err == nil
	if op == wg.Rcv && timedout(err) {
		lastSuccessfulRead := h.latestRx.Load()
		writeElapsedMs := h.latestTx.Load() - lastSuccessfulRead // may be negative
		// if status is "up" but writes (Snd) have not yet happened
		// then reads (Rcv) are expected to timeout; so ignore them
		if lastSuccessfulRead <= 0 || writeElapsedMs > markTNTAfterMillis {
			s = TNT // writes succeeded; but reads have never or not in the past 20s
		} else {
			s = TZZ // wirtes and reads have succeeded in the recent past
		}
	} else if err != nil {
		s = TKO // failing
	}

	if s == TOK {
		if op == wg.Rcv { // read
			h.latestRx.Store(now())
		} else if op == wg.Snd { // write
			h.latestTx.Store(now())
		}
		writeElapsedMs := h.latestTx.Load() - h.latestRx.Load() // may be negative
		// if no reads since last write, mark as unresponsive
		if writeElapsedMs > markTNTAfterMillis {
			s = TNT
		}
	} else if s != TUP {
		if op == wg.Rcv {
			h.errRx.Add(1)
		} else if op == wg.Snd {
			h.errTx.Add(1)
		}
		if n := h.remote.Load().MaybeRefresh(); n > 0 {
			log.I("wg: %s (%s) listener: %s, state: %s; refreshed n domains: %d",
				h.id, h.viaStatus(), op, pxstatus(s), n)
		}
	}

	h.status.Store(s)
}

// func Handle(), GetAddr(), Dialer(), Reaches(), Stop(),
// OnProtoChange(), Ping(), Stats(), Router() impl by wgproxy.

// now returns the current time in unix millis
func now() int64 {
	return time.Now().UnixMilli()
}

func (w *wgproxy) resetMtu(via Proxy) error {
	return w.maybeResetMtu(via, false /*dryrun*/)
}

func (w *wgproxy) maybeResetMtu(via Proxy, dryrun bool) error {
	// mtu needed to tunnel this wg
	mtuNeededByUs := int(w.desiredmtu.Load())
	mtuAvailFromNet := int(w.netmtu.Load())
	mtuAvailable := mtuAvailFromNet
	hopping := false // tunnled via another proxy
	viaid := idstr(via)

	note := log.I
	if dryrun {
		note = log.D
	}

	if via != nil {
		// mtu affordable by via (routerMtu = endpointMtu + wgHeader)
		if mtuAvailFromHop, err := via.Router().MTU(); err != nil {
			return err
		} else {
			mtuAvailable = calcTunMtu(mtuAvailFromHop)
			hopping = true
			note("wg: %s proxy: hopping %s; mtu(needed: %d / net: %d); hopmtu(avail: %d / tot: %d)",
				w.id, viaid, mtuNeededByUs, mtuAvailFromNet, mtuAvailable, mtuAvailFromHop)
		}
	}

	minmtu := minmtu4
	if has6 := w.IP6(); has6 {
		minmtu = minmtu6
	}
	if mtuAvailable < minmtu {
		log.W("wg: %s proxy: not hopping %s; needs %d; mtu(%d) < min(%d)", w.id, viaid, mtuAvailable, minmtu)
		return errHopMtuInsufficient
	}

	if hopping && mtuNeededByUs > mtuAvailable {
		note("wg: %s proxy: maybe hopping %s; mtu(needed: %d >> avail: %d << min: %d); set to avail",
			w.id, viaid, mtuNeededByUs, mtuAvailable, minmtu)
		mtuNeededByUs = mtuAvailable
	} // else: mtu needed is well within the hop's / network's capacity

	finalMtu := reconcileMtu(mtuAvailable, mtuNeededByUs, minmtu)
	if finalMtu <= NOMTU {
		log.W("wg: %s proxy: not hopping %s; mtu(%d or %d) <= NOMTU(%d)", w.id, viaid, mtuNeededByUs, mtuAvailable, finalMtu)
		return errHopMtuInsufficient
	}

	if !dryrun {
		w.ep.SetMTU(uint32(finalMtu))
		w.wgtun.events <- tun.EventMTUUpdate
	}
	note("wg: %s proxy: hopping %s; mtu(needed:%d, avail: %d => final: %d); hopping? %t, dryrun? %t",
		w.id, viaid, mtuNeededByUs, mtuAvailable, finalMtu, hopping, dryrun)
	return nil
}

// Returns wg header (80 bytes) minus min(underlay, overlay).
// Returns NOMTU if underlay is <= NOMTU.
// Returns minoverlay if overlay is <= NOMTU.
func reconcileMtu(underlay, overlay, minoverlay int) int {
	if underlay < overlay { // underlay may be NOMTU
		return max(underlay-80, NOMTU) // underlay may be way smaller than overlay
	}
	return calcTunMtu2(overlay, minoverlay) // overlay may be NOMTU, but that's okay
}

// May return NOMTU if netmtu-size(wg header) is <= NOMTU.
func calcTunMtu(netmtu int) int {
	return calcTunMtu2(netmtu, NOMTU)
}

// github.com/tailscale/tailscale/blob/92d3f64e95/net/tstun/mtu.go
func calcTunMtu2(netmtu, min int) int {
	// uint32(mtu) - 80 is the maximum payload size of a WireGuard packet.
	return max(min-80, netmtu-80) // 80 is the overhead of the WireGuard header
}

func calcNetMtu(tunmtu int) int {
	return max(minmtu6, tunmtu+80) // 80 is the overhead of the WireGuard header
}

func timedout(err error) bool {
	x, ok := err.(net.Error)
	return ok && x.Timeout()
}

func logev(err error) log.LogFn {
	if err != nil {
		return log.E
	}
	return log.VV
}

func loged(err error) log.LogFn {
	if err != nil {
		return log.E
	}
	return log.D
}

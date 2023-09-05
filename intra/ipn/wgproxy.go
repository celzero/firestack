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
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"

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
	// epsize is the size of the channel endpoint.
	epsize = 1024
	// eventssize is the size of the events channel.
	eventssize = 16
	// wgnic is the id of the WireGuard network interface.
	wgnic = 999
	// missing wg interface address.
	noaddr = ""
	// min mtu for ipv6
	minmtu6 = uint32(1280)
)

type wgtun struct {
	id             string
	addrs          []*netip.Prefix
	status         int
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	dnsaddrs       []*netip.Addr
	hasV4, hasV6   bool
}

var _ WgProxy = (*wgproxy)(nil)

type wgproxy struct {
	*wgtun
	*device.Device
}

type WgProxy interface {
	Proxy
	tun.Device
	canUpdate(txt string) bool
	IpcSet(txt string) error
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

func (w *wgproxy) Refresh() (err error) {
	if err = w.Device.Down(); err != nil {
		log.E("proxy: wg: !refresh(%s): down: %v", w.id, err)
		return
	}
	if err = w.Device.Up(); err != nil {
		log.E("proxy: wg: !refresh(%s): up: %v", w.id, err)
		return
	}
	return
}

func (w *wgproxy) canUpdate(txt string) bool {
	if w.status == END {
		log.W("proxy: wg: !canUpdate(%s): END; status(%d)", w.id, w.status)
		return false
	}

	// str copy: go.dev/play/p/eO814kGGNtO
	cptxt := txt
	ifaddrs, dnsaddrs, mtu, err := wgIfConfigOf(&cptxt)
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
	if len(w.dnsaddrs) != len(dnsaddrs) {
		log.D("proxy: wg: !canUpdate(%s): len(dnsaddrs) %d != %d", w.id, len(dnsaddrs), len(w.dnsaddrs))
		return false
	}
	for _, indnsaddr := range dnsaddrs {
		var dnsok bool
		for _, a := range w.dnsaddrs {
			if indnsaddr.Compare(*a) == 0 {
				dnsok = true
				break
			}
		}
		if !dnsok {
			log.D("proxy: wg: !canUpdate(%s): new dnsaddrs (%s) != (%s)", w.id, dnsaddrs, w.dnsaddrs)
			return false
		}
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
	tag := WG + id
	logger := &device.Logger{
		Verbosef: log.Of(tag, log.N),
		Errorf:   log.Of(tag, log.E),
	}
	if settings.Debug {
		logger.Verbosef = log.Of(tag, log.V)
	}
	return logger
}

func wgIfConfigOf(txtptr *string) (ifaddrs []*netip.Prefix, dnsaddrs []*netip.Addr, mtu int, err error) {
	txt := *txtptr
	pcfg := strings.Builder{}
	r := bufio.NewScanner(strings.NewReader(txt))
	for r.Scan() {
		line := r.Text()
		if len(line) <= 0 {
			// Blank line means terminate operation.
			if (len(ifaddrs) <= 0) || (len(dnsaddrs) <= 0) || (mtu <= 0) {
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
		case "address":
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
					ifaddrs = append(ifaddrs, &ipnet)
				} else { // add prefix to address
					if ipnet, err = ip.Prefix(ip.BitLen()); err != nil {
						return
					}
					ifaddrs = append(ifaddrs, &ipnet)
				}
			}
		case "dns":
			var ip netip.Addr
			vv := strings.Split(v, ",")
			for _, str := range vv {
				str = strings.TrimSpace(str)
				if ip, err = netip.ParseAddr(str); err != nil {
					return
				}
				dnsaddrs = append(dnsaddrs, &ip)
			}
		case "mtu":
			if mtu, err = strconv.Atoi(v); err != nil {
				return
			}
		default:
			pcfg.WriteString(line + "\n")
		}
	}
	*txtptr = pcfg.String()
	if err == nil && (len(ifaddrs) <= 0) || (len(dnsaddrs) <= 0) || (mtu <= 0) {
		err = errProxyConfig
	}
	return
}

func bindWgSockets(wgdev *device.Device, ctl protect.Controller) bool {
	var ok4, ok6 bool

	// ref: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/bind_std.go#L130
	// bind: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L180
	// protect: https://github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java#L316
	bind := wgdev.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		log.E("proxy: wg: bind: failed to get wg socket")
		return false
	}

	if fd4, err := bind.PeekLookAtSocketFd4(); err != nil {
		log.W("proxy: wg: bind4: failed to get wg4 socket %v", err)
	} else {
		ctl.Bind4(fd4)
		ok4 = true
	}

	if fd6, err := bind.PeekLookAtSocketFd6(); err != nil {
		log.W("proxy: wg: bind6: failed to get wg6 socket %v", err)
	} else {
		ctl.Bind6(fd6)
		ok6 = true
	}

	return ok4 || ok6
}

// ref: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L76
func NewWgProxy(id string, ctl protect.Controller, cfg string) (w WgProxy, err error) {
	ifaddrs, dnsaddrs, mtu, err := wgIfConfigOf(&cfg)
	uapicfg := cfg
	if err != nil {
		log.E("proxy: wg: failed to get addrs from config %v", err)
		return nil, err
	}

	wgtun, err := makeWgTun(id, ifaddrs, dnsaddrs, mtu)
	if err != nil {
		log.E("proxy: wg: failed to create tun %v", err)
		return nil, err
	}

	wgdev := device.NewDevice(wgtun, wg.NewBind(), wglogger(id))

	err = wgdev.IpcSet(uapicfg)
	if err != nil {
		log.E("proxy: wg: failed to ipc-set %v", err)
		return nil, err
	}

	// github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L99
	wgdev.DisableSomeRoamingForBrokenMobileSemantics()

	err = wgdev.Up()
	if err != nil {
		log.E("proxy: wg: failed init %v", err)
		return nil, err
	}

	// nb: call after StdNetBind conn has been "Open"ed
	// not needed for wg.NewBind2; see: wg:wgconn2.go
	bindok := bindWgSockets(wgdev, ctl)

	w = &wgproxy{
		wgtun,
		wgdev,
	}

	log.D("proxy: wg: new %s / bound? %t; addrs(%v) mtu(%d) / v4(%t) v6(%t)", id, bindok, ifaddrs, mtu, wgtun.hasV4, wgtun.hasV6)

	return
}

// ref: github.com/WireGuard/wireguard-go/blob/469159ecf7/tun/netstack/tun.go#L54
func makeWgTun(id string, ifaddrs []*netip.Prefix, dnsaddrs []*netip.Addr, mtu int) (*wgtun, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	// uint32(mtu) - 80 is the maximum payload size of a WireGuard packet.
	tunmtu := min(minmtu6, uint32(mtu)-80) // 80 is the overhead of the WireGuard header

	s := stack.New(opts)
	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	ep := channel.New(epsize, tunmtu, "")
	t := &wgtun{
		id:             id,
		addrs:          ifaddrs,
		ep:             ep,
		stack:          s,
		events:         make(chan tun.Event, eventssize),
		incomingPacket: make(chan *buffer.View),
		dnsaddrs:       dnsaddrs,
		mtu:            int(tunmtu),
	}
	// see WriteNotify below
	ep.AddNotify(t)

	if err := s.CreateNIC(wgnic, ep); err != nil {
		return nil, fmt.Errorf("wg: create nic: %v", err)
	}

	processed := make(map[string]bool)
	for _, ipnet := range ifaddrs {
		ip := ipnet.Addr()
		if processed[ipnet.String()] {
			log.W("proxy: wg: skipping duplicate ip %v for ifaddr %v", ip, ipnet)
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
			return nil, fmt.Errorf("wg: add addr(%v): %v", ip, err)
		}
		t.hasV4 = t.hasV4 || ip.Is4()
		t.hasV6 = t.hasV6 || ip.Is6()
		log.D("proxy: wg: added addr(%v) / v4(%t)/v6(%t)", ip, ip.Is4(), ip.Is6())
	}
	if t.hasV4 {
		s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: wgnic})
	}
	if t.hasV6 {
		s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: wgnic})
	}

	// commence the wireguard state machine
	t.events <- tun.EventUp

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
		log.W("wg: tun: read closed")
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		log.W("wg: tun: read(%d): %v", n, err)
		return 0, err
	}

	log.V("wg: tun: read(%d)", n)
	sizes[0] = n
	return 1, nil
}

func (tun *wgtun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			log.D("wg: tun: write: empty packet")
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
			log.W("wg: tun: write: unknown proto %d; discard %d", protoid, sz)
			return 0, syscall.EAFNOSUPPORT
		}
		log.V("wg: tun: write: sz(%d); proto %d", sz, protoid)
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

	log.V("wg: tun: write: notify sz(%d)", view.Size())
	tun.incomingPacket <- view
}

func (tun *wgtun) Close() error {
	// TODO: move this to wgproxy.Close()?
	// should work: go.dev/play/p/HeU5EvzAjnv
	if tun.status == END {
		log.W("proxy: wg: tun: already closed?")
		return errProxyStopped
	}

	log.D("proxy: wg: tun: closing...")
	tun.status = END
	tun.stack.RemoveNIC(wgnic)

	// if tun.events != nil {
	// panics; is it closed by device.Device.Close()?
	// close(tun.events) }

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	// stack closes the endpoint, too via nic.go#remove?
	// tun.ep.Close()
	tun.stack.Close()
	// wait for stack to close?
	// github.com/tailscale/tailscale/blob/836f932e/wgengine/netstack/netstack.go#L223
	// TODO: tun.stack.Wait()

	log.I("proxy: wg: tun: closed")
	return nil
}

func (tun *wgtun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *wgtun) BatchSize() int {
	return 1
}

// implements Proxy

func (h *wgtun) Dial(network, address string) (c Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	log.D("wg: dial: start %s %s", network, address)

	if c, err = h.DialContext(context.Background(), network, address); err != nil {
		h.status = TKO
	} else {
		h.status = TOK
	}

	log.I("wg: dial: end %s %s; err %v", network, address, err)

	return
}

func (h *wgtun) ID() string {
	return h.id
}

func (h *wgtun) GetAddr() string {
	if len(h.addrs) == 0 {
		return noaddr
	}
	return h.addrs[0].String()
}

func (h *wgtun) Type() string {
	return WG
}

func (h *wgtun) Status() int {
	return h.status
}

// func Stop() error is impl by wgproxy

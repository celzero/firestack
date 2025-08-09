// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/multihost"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	tx "github.com/txthinking/socks5"
	"golang.org/x/net/proxy"
)

type socks5 struct {
	NoFwd       // no forwarding/listening
	NoDNS       // no dns
	SkipRefresh // no refresh
	GW          // dual stack gateway

	id       string                 // unique identifier
	opts     *settings.ProxyOptions // connect options
	d        protect.RDialer        // dialer to this upstream proxy
	outbound []proxy.Dialer         // outbound dialers via this upstream proxy
	px       ProxyProvider          // proxy provider
	viaID    *core.Volatile[string] // hop id
	via      *core.WeakRef[Proxy]   // hop proxy
	lastdial time.Time              // last time this transport attempted a connection
	status   *core.Volatile[int]    // status of this transport
	done     context.CancelFunc     // cancel func
}

type socks5tcpconn struct {
	*tx.Client
}

type socks5udpconn struct {
	*tx.Client
}

var _ core.TCPConn = (*socks5tcpconn)(nil)
var _ core.UDPConn = (*socks5udpconn)(nil)
var _ net.Conn = (*socks5tcpconn)(nil) // needed by golang/http transport
var _ net.Conn = (*socks5udpconn)(nil)

func (c *socks5tcpconn) CloseRead() error {
	if c.Client != nil && c.Client.TCPConn != nil {
		core.CloseOp(c.Client.TCPConn, core.CopR)
		return nil
	}
	return errNoProxyConn
}

func (c *socks5tcpconn) CloseWrite() error {
	if c.Client != nil && c.Client.TCPConn != nil {
		core.CloseOp(c.Client.TCPConn, core.CopW)
		return nil
	}
	return errNoProxyConn
}

// WriteFrom writes b to TUN using addr as the source.
func (c *socks5udpconn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if c.Client != nil && c.Client.UDPConn != nil {
		if uconn, ok := c.Client.UDPConn.(*net.UDPConn); ok {
			return uconn.WriteTo(b, addr)
		}
		return c.Client.UDPConn.Write(b)
	}
	return 0, errNoProxyConn
}

// ReceiveTo is incoming TUN packet b to be sent to addr.
func (c *socks5udpconn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if c.Client != nil && c.Client.UDPConn != nil {
		if uconn, ok := c.Client.UDPConn.(*net.UDPConn); ok {
			return uconn.ReadFrom(b)
		}
		return 0, nil, errNotUDPConn
	}
	return 0, nil, errNoProxyConn
}

func NewSocks5Proxy(id string, ctx context.Context, ctl protect.Controller, px ProxyProvider, po *settings.ProxyOptions) (_ *socks5, err error) {
	tx.Debug = settings.Debug
	if po == nil {
		log.W("proxy: err setting up socks5(%v): %v", po, err)
		return nil, errMissingProxyOpt
	}

	ctx, done := context.WithCancel(ctx)

	portnumber, _ := strconv.Atoi(po.Port)
	mh := multihost.New(id)
	mh.Add([]string{po.Host, po.IP}) // resolves if ip is name

	var clients []proxy.Dialer
	// x.net.proxy doesn't yet support udp
	// github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
	// if po.Auth.User and po.Auth.Password are empty strings, the upstream
	// socks5 server may throw err when dialing with golang/net/x/proxy;
	// although, txthinking/socks5 deals gracefully with empty auth strings
	// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
	for _, ip := range mh.PreferredAddrs() {
		ipport := netip.AddrPortFrom(ip.Addr(), uint16(portnumber))
		c, cerr := tx.NewClient(ipport.String(), po.Auth.User, po.Auth.Password, tcptimeoutsec, udptimeoutsec)
		if cerr != nil {
			err = errors.Join(err, cerr)
		} else {
			clients = append(clients, c)
		}
	}

	if len(clients) == 0 && err != nil {
		defer done()
		log.W("proxy: err creating socks5 for %v (opts: %v): %v",
			mh, po, err)
		return nil, err
	}

	// always with a network namespace aware dialer
	dialer := protect.MakeNsRDial(id, ctx, ctl)
	h := &socks5{
		id:       id,
		d:        dialer,
		px:       px,
		outbound: clients,
		viaID:    core.NewZeroVolatile[string](),
		opts:     po,
		done:     done,
	}

	tx.DialTCP = h.txdial // h.outbound uses this
	tx.DialUDP = h.txdial // h.outbound uses this

	via, err := core.NewWeakRef(h.viafor, viaok)
	if err != nil {
		defer done()
		log.W("proxy: socks5: %s err via: %v", h.ID(), err)
		return nil, err
	}
	h.via = via

	log.D("proxy: socks5: created %s with clients(%d), opts(%s)",
		h.id, len(clients), po)

	return h, nil
}

func (h *socks5) viafor() *Proxy {
	return viafor(h.id, h.viaID.Load(), h.px)
}

func (h *socks5) swapVia(new Proxy) (old Proxy) {
	return swapVia(h.id, new, h.viaID, h.via)
}

func (h *socks5) txdial(n, src, dst string) (c net.Conn, err error) {
	who := idstr(h)
	if usevia(h.viaID) {
		if v, vok := h.via.Get(); vok {
			who = idstr(v)
			c, err = v.DialBind(n, src, dst)
		} else {
			err = errNoHop
			if removeViaOnErrors {
				h.Hop(nil, false /*dryrun*/) // stale; unset
			}
			log.W("proxy: socks5: %s via(%s) failing...", h.id, idhandle(v))
		}
	} else {
		c, err = h.d.DialBind(n, src, dst)
	}
	logei(err)("proxy: socks5: %s dial(%s) from %s => %s (via %s); err? %v", h.id, n, h.GetAddr(), dst, who, err)
	return
}

// Handle implements Proxy.
func (h *socks5) Handle() uintptr {
	return core.Loc(h)
}

// DialerHandle implements Proxy.
func (h *socks5) DialerHandle() uintptr {
	return core.Loc(h.d)
}

// Dial implements Proxy.
func (h *socks5) Dial(network, addr string) (c protect.Conn, err error) {
	return h.dial(network, "", addr)
}

// DialBind implements Proxy.
func (h *socks5) DialBind(network, local, remote string) (c protect.Conn, err error) {
	log.D("proxy: socks5: %s dialbind(%s) %s => %s; not supported",
		h.ID(), network, local, remote)
	return h.dial(network, local, remote)
}

// todo: bind to local
func (h *socks5) dial(network, _, remote string) (c protect.Conn, err error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}

	h.lastdial = time.Now()
	// todo: tx.Client can only dial in to ip:port and not host:port even for server addr
	// tx.Client.Dial does not support dialing into client addr as hostnames
	if c, err = dialers.ProxyDials(h.outbound, network, remote); err == nil {
		// github.com/txthinking/socks5/blob/39268fae/client.go#L15
		if uc, ok := c.(*tx.Client); ok {
			if uc.UDPConn != nil { // a udp conn will always have an embedded tcp conn
				c = &socks5udpconn{uc}
			} else if uc.TCPConn != nil { // a tcp conn will never also have a udp conn
				c = &socks5tcpconn{uc}
			} else {
				log.W("proxy: socks5: %s conn not tcp nor udp %s => %s",
					h.ID(), h.GetAddr(), remote)
				core.CloseConn(c)
				c = nil
				err = errNoProxyConn
			}
		} else {
			log.W("proxy: socks5: %s conn not a tx.Client(%s) %s => %s",
				h.ID(), network, h.GetAddr(), remote)
			core.CloseConn(c)
			c = nil
			err = core.OneErr(err, errNoProxyConn)
		}
	} else {
		log.W("proxy: socks5: %s dial(%s) failed %s => %s: %v",
			h.ID(), network, h.GetAddr(), remote, err)
	}
	defer localDialStatus(h.status, err)
	return
}

// Dialer implements Proxy.
func (h *socks5) Dialer() protect.RDialer {
	return h
}

// ID implements x.Proxy.
func (h *socks5) ID() *x.Gostr {
	return x.StrOf(h.id)
}

// Type implements x.Proxy.
func (h *socks5) Type() *x.Gostr {
	return x.StrOf(SOCKS5)
}

// Router implements x.Proxy.
func (h *socks5) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *socks5) Reaches(hostportOrIPPortCsv *x.Gostr) bool {
	return Reaches(h, hostportOrIPPortCsv.V())
}

// Hop implements Proxy.
func (h *socks5) Hop(p Proxy, dryrun bool) error {
	if p == nil {
		if !dryrun {
			old := h.swapVia(nil)
			log.I("socks5: hop(%s) removed", idhandle(old))
		}
		return nil
	}
	if p.Status() == END {
		return errProxyStopped
	}

	if !dryrun {
		old := h.swapVia(p)
		log.I("socks5: hop %s => %s", idhandle(old), idhandle(p))
	}
	return nil
}

// Via implements x.Router.
func (h *socks5) Via() (x.Proxy, error) {
	if v := h.via.Load(); v != nil {
		return v, nil
	}
	return nil, errNoHop
}

// GetAddr implements x.Proxy.
func (h *socks5) GetAddr() *x.Gostr {
	return x.StrOf(h.opts.IPPort)
}

// Status implements Proxy.
func (h *socks5) Status() int {
	s := h.status.Load()
	if s != END && idling(h.lastdial) {
		return TZZ
	}
	return s
}

// Pause implements x.Proxy.
func (h *socks5) Pause() bool {
	st := h.status.Load()
	if st == END {
		log.W("proxy: socks5: pause called when stopped")
		return false
	}

	ok := h.status.Cas(st, TPU)
	log.I("proxy: socks5: paused? %t", ok)
	return ok
}

// Resume implements x.Proxy.
func (h *socks5) Resume() bool {
	st := h.status.Load()
	if st != TPU {
		log.W("proxy: socks5: resume called when not paused; status %d", st)
		return false
	}

	ok := h.status.Cas(st, TUP)
	log.I("proxy: socks5: resumed? %t", ok)
	return ok
}

// Stop implements Proxy.
func (h *socks5) Stop() error {
	h.status.Store(END)
	h.done()
	log.I("proxy: socks5: stopped %s", h.id)
	return nil
}

// OnProtoChange implements Proxy.
func (h *socks5) OnProtoChange(_ LinkProps) (string, bool) {
	if err := candial(h.status); err != nil {
		return "", false
	}
	return h.opts.FullUrl(), true
}

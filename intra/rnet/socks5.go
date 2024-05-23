// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rnet

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	tx "github.com/txthinking/socks5"
)

var _ tx.Handler = (*socks5)(nil)

type socks5 struct {
	*tx.Server
	id        string
	url       string
	rdial     *protect.RDial
	hdl       *socks5handler
	summaries map[*tx.UDPExchange]*ServerSummary
	listener  ServerListener
	status    int
}

type socks5handler struct {
	*tx.DefaultHandle
	px ipn.Proxy
}

func newSocks5Server(id, x string, ctl protect.Controller, listener ServerListener) (*socks5, error) {
	var host string
	var usr string
	var pwd string

	rdial := protect.MakeNsRDial(id, ctl)
	tx.Dial = rdial // overriden by h.Hop

	u, err := url.Parse(x)
	if err != nil {
		return nil, err
	}
	host = u.Host      // host
	if u.User != nil { // usr, pwd
		usr = u.User.Username()    // may be empty
		pwd, _ = u.User.Password() // may be empty
	}
	// unused in our case; usage: github.com/txthinking/brook/issues/988
	remoteip := ""
	hdl := &socks5handler{
		DefaultHandle: &tx.DefaultHandle{}, // not used; see dial, TCPHandle, and UDPHandle
	}
	server, _ := tx.NewClassicServer(host, remoteip, usr, pwd, tcptimeoutsec, udptimeoutsec)

	hasauth := len(usr) > 0 || len(pwd) > 0
	log.I("svcsocks5: new %s listening at %s; auth?", id, host, hasauth)
	return &socks5{
		Server:    server,
		id:        id,
		url:       host,
		rdial:     rdial,
		hdl:       hdl,
		listener:  listener,
		summaries: make(map[*tx.UDPExchange]*ServerSummary),
		status:    SOK,
	}, nil
}

func (h *socks5) Hop(p x.Proxy) error {
	if h.status == END {
		log.D("svcsocks5: hop: %s not running", h.ID())
		return errServerEnd
	}
	if p == nil {
		h.hdl.px = nil
		tx.Dial = h.rdial
	} else if pp, ok := p.(ipn.Proxy); ok {
		h.hdl.px = pp
		tx.Dial = pp.Dialer()
	} else {
		log.E("svcsocks5: hop: %s; failed: %T not ipn.Proxy", h.ID(), p)
		return errNotProxy
	}
	log.D("svcsocks5: hop: %s over proxy? %t via %s", h.ID(), p != nil, h.GetAddr())
	return nil
}

func (h *socks5) Start() error {
	if h.status != END {
		return errSvcRunning
	}
	h.status = SOK
	go func() {
		err := h.Server.ListenAndServe(h)
		log.I("svcsocks5: %s exited; err? %v", h.ID(), err)
		h.status = END
	}()
	log.I("svcsocks5: %s started %s", h.ID(), h.GetAddr())
	return nil
}

func (h *socks5) Stop() error {
	err := h.Server.Shutdown()
	h.status = END
	log.I("svcsocks5: %s stopped; err? %v", h.ID(), err)
	return err
}

func (h *socks5) Refresh() error {
	err1 := h.Stop()
	time.Sleep(3 * time.Second) // arbitrary wait
	err2 := h.Start()

	log.I("svcsocks5: %s refreshed; errs? %v; %v", h.ID(), err1, err2)

	if err2 != nil {
		return err2
	}
	return err1
}

func (h *socks5) ID() string {
	return h.id
}

func (h *socks5) GetAddr() string {
	px := h.hdl.px
	if px != nil {
		return px.GetAddr()
	}
	return h.url
}

func (h *socks5) Status() int {
	return h.status
}

func (h *socks5) Type() string {
	px := h.hdl.px
	if px != nil {
		return PXSOCKS5
	}
	return SVCSOCKS5
}

// Implements tx.Handler
func (h *socks5) TCPHandle(server *tx.Server, ingress *net.TCPConn, req *tx.Request) error {
	if err := h.candial(); err == nil {
		return h.tcphandle(server, ingress, req)
	} else {
		return err
	}
}

// Implement tx.Handler
func (h *socks5) UDPHandle(server *tx.Server, ingress *net.UDPAddr, pkt *tx.Datagram) error {
	if err := h.candial(); err == nil {
		return h.udphandle(server, ingress, pkt)
	} else {
		return err
	}
}

func (h *socks5) dial(network, src, dst string) (cid string, conn net.Conn, err error) {
	if err = h.candial(); err != nil {
		return
	}
	tab := h.route(network, src, dst)
	if tab.Block {
		err = errBlocked
		return
	}
	px := h.hdl.px
	if px != nil {
		conn, err = px.Dialer().Dial(network, dst)
	} else {
		conn, err = h.rdial.Dial(network, dst)
	}
	return tab.CID, conn, err
}

func (h *socks5) pid() (x string) {
	px := h.hdl.px
	if px != nil {
		x = px.ID()
	}
	return
}

func (h *socks5) route(network, src, dst string) *Tab {
	return h.listener.Route(h.id, h.pid(), network, src, dst)
}

func (h *socks5) candial() error {
	if h.Status() != END {
		return errProxyEnd // no
	}
	px := h.hdl.px
	if px != nil && px.Status() == ipn.END {
		return errProxyEnd // no
	}
	return nil // yes
}

func (h *socks5) setDeadline(c net.Conn, secs int) error {
	if secs == 0 { // no op
		return nil
	}
	ttl := time.Duration(secs) * time.Second
	return c.SetDeadline(time.Now().Add(ttl))
}

type pipefin struct {
	ex  int   // bytes exchanged
	err error // error, if any
}

func (h *socks5) pipe(r, w net.Conn, finch chan<- pipefin) {
	bptr := core.Alloc()
	bf := *bptr
	bf = bf[:cap(bf)]
	defer func() {
		*bptr = bf
		core.Recycle(bptr)
	}()
	ex := 0
	laddr := r.LocalAddr()
	raddr := w.RemoteAddr()
	for {
		if err := h.setDeadline(r, tcptimeoutsec); err != nil {
			finch <- pipefin{ex, err}
			break
		}
		n, err := r.Read(bf[:])
		ex += n
		if err != nil {
			log.E("svcsocks5: tcp: %s; read %s; err: %v", h.ID(), laddr, err)
			finch <- pipefin{ex, err}
			break
		}
		if _, err := w.Write(bf[0:n]); err != nil {
			log.E("svcsocks5: tcp: %s; write %s; err: %v", h.ID(), raddr, err)
			finch <- pipefin{ex, err}
			break
		}
		log.V("svcsocks5: tcp: %s; %s -> %s; %d bytes", h.ID(), laddr, raddr, n)
	}
}

// Adopted from tx.DefaultHandle with the only changes are
// 1. ipn.Proxy as the dialer
// 2. buffers are allocated from core.Alloc()
func (h *socks5) tcphandle(s *tx.Server, ingress *net.TCPConn, r *tx.Request) (err error) {
	if r.Cmd == tx.CmdConnect {
		var cid string
		var egress *net.TCPConn
		cid, egress, err = h.Connect(r, ingress)
		summary := serverSummary(h.Type(), h.ID(), h.pid(), cid)
		defer func() {
			summary.done(err)
			go h.listener.OnComplete(summary)
		}()

		log.D("svcsocks5: proxy-tcp: %s; socks5-connect %s", cid, r.Address())

		if err != nil {
			h.status = SKO
			log.E("svcsocks5: proxy-tcp: %s; connect %s; err: %v", cid, r.Address(), err)
			return err
		}
		// c is closed by the caller
		defer clos(egress)

		finrxch := make(chan pipefin, 1)
		fintxch := make(chan pipefin, 1)
		go h.pipe(egress, ingress, finrxch) // read from egress, write to ingress
		go h.pipe(ingress, egress, fintxch) // read from ingress, write to egress
		finrx := <-finrxch
		fintx := <-fintxch

		err = errors.Join(finrx.err, fintx.err)

		summary.Rx = finrx.ex
		summary.Tx = fintx.ex

		return err
	}
	if r.Cmd == tx.CmdUDP {
		log.D("svcsocks5: proxy-tcp via udp: %s; socks5-tcp-udp %s", h.ID(), r.Address())
		caddr, err := r.UDP(ingress, s.ServerAddr)
		if err != nil {
			h.status = SKO
			return err
		}

		ch := make(chan byte)
		defer close(ch)

		s.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer s.AssociatedUDP.Delete(caddr.String())

		n, err := io.Copy(io.Discard, ingress)

		log.D("svcsocks: tcp: %s tcp that udp %s associated closed %d; err? %v", h.ID(), caddr, n, err)
		return nil
	}
	return tx.ErrUnsupportCmd
}

func (h *socks5) udphandle(s *tx.Server, addr *net.UDPAddr, pkt *tx.Datagram) (err error) {
	cid := h.ID() // init connection id to server id, for logging purposes
	src := addr.String()
	var ch chan byte

	if s.LimitUDP { // always false, for now
		any, ok := s.AssociatedUDP.Get(src)
		if !ok {
			return fmt.Errorf("udp addr %s not associated with tcp", src)
		}
		ch, ok = any.(chan byte)
		if !ok {
			return fmt.Errorf("udp addr %s not associated with tcp; ch missing", src)
		}
	}

	send := func(egress *tx.UDPExchange, data []byte) error {
		ueladdr := egress.RemoteConn.LocalAddr()
		ueraddr := egress.RemoteConn.RemoteAddr()
		uecaddr := egress.ClientAddr
		ssu := h.summaries[egress]
		select {
		case _, ok := <-ch:
			return fmt.Errorf("udp addr %s not associated with tcp; ch ok? %t", src, ok)
		default:
			// writing to egress conn
			n, werr := egress.RemoteConn.Write(data)
			if ssu != nil {
				ssu.Tx += n
			}
			log.D("svcsocks5: udp: %s; data sent; (err: %v / summary? %t)? client: %s server: %s remote: %s sz: %d", cid, werr, ssu != nil, uecaddr, ueladdr, ueraddr, n)
			if werr != nil {
				return werr
			}
		}
		return nil
	}

	dst := pkt.Address()
	tuple4 := src + dst
	var egress *tx.UDPExchange
	iue, ok := s.UDPExchanges.Get(tuple4)
	if ok {
		if egress, ok = iue.(*tx.UDPExchange); ok {
			return send(egress, pkt.Data)
		}
	}

	ssu := serverSummary(h.Type(), h.ID(), h.pid(), cid)
	defer func() {
		ssu.done(err)
		go h.listener.OnComplete(ssu)
	}()

	log.D("svcsocks5: udp: %s; dst %s", cid, dst)
	cid, uc, err := h.dial("udp", src, dst)
	if err != nil {
		return err
	}

	rc, ok := uc.(*net.UDPConn)
	if !ok {
		return errNotUdp
	}

	egress = &tx.UDPExchange{
		ClientAddr: addr, // same as src
		RemoteConn: rc,
	}
	h.summaries[egress] = ssu
	log.D("svcsocks5: udp: %s; remote conn for client: %s server: %s remote: %s", cid, addr, egress.RemoteConn.LocalAddr(), pkt.Address())
	if err := send(egress, pkt.Data); err != nil {
		log.E("svcsocks5: udp: %s; send pkt %d to remote: %s; err %v", cid, len(pkt.Data), egress.RemoteConn.RemoteAddr(), err)
		delete(h.summaries, egress)
		clos(egress.RemoteConn) // TODO: clos(egress) instead?
		return err
	}
	s.UDPExchanges.Set(src+dst, egress, -1)

	go func(ue *tx.UDPExchange, dst string) {
		bptr := core.Alloc()
		b := *bptr
		b = b[:cap(b)]
		defer func() {
			delete(h.summaries, ue)

			clos(ue.RemoteConn)
			s.UDPExchanges.Delete(src + dst)

			*bptr = b
			core.Recycle(bptr)
		}()

		ueladdr := ue.RemoteConn.LocalAddr()
		ueraddr := ue.RemoteConn.RemoteAddr()
		uecaddr := ue.ClientAddr
		for {
			select {
			case _, ok = <-ch:
				log.D("svcsocks5: udp: %s; tcp to udp addr %s associated closed; ch ok? %t", cid, uecaddr, ok)
				return
			default:
				if err := h.setDeadline(ue.RemoteConn, s.UDPTimeout); err != nil {
					return
				}
				// reading from egress
				n, err := ue.RemoteConn.Read(b[:])
				if err != nil {
					log.E("svcsocks5: udp: %s; read err: %v", cid, err)
					return
				}
				ssu.Rx += n
				log.D("svcsocks5: udp: %s; got data; client: %s server: %s remote: %s data: %d", cid, uecaddr, ueladdr, ueraddr, n)
				a, addr, port, err := tx.ParseAddress(dst)
				if err != nil {
					log.E("svcsocks5: udp: %s; parse-addr err? %v", cid, err)
					return
				}
				d1 := tx.NewDatagram(a, addr, port, b[:n])
				// writing to ingress
				if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
					log.E("svcsocks5: udp: %s; write err: %v", cid, err)
					return
				}
				log.V("svcsocks5: udp: %s; data sent; client: %s server: %s remote: %s data: %#v %#v %#v %#v %#v %#d datagram address: %s", cid, uecaddr, ueladdr, ueraddr, d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, len(d1.Data), d1.Address())
			}
		}
	}(egress, dst)
	return nil
}

func (h *socks5) Connect(r *tx.Request, w *net.TCPConn) (cid string, rc *net.TCPConn, err error) {
	log.D("svcsocks5: tcp: %s; dial", h.ID(), r.Address())
	raddr := w.RemoteAddr()
	if raddr == nil {
		log.W("svcsocks5: tcp: %s; err no remote addr", h.ID())
		h.status = SKO
		err = errNoAddr
		return
	}

	var tc net.Conn // egress
	cid, tc, err = h.dial("tcp", raddr.String(), r.Address())
	if err != nil {
		h.status = SKO

		log.W("svcsocks5: tcp: %s; dial remote %s; err: %v", cid, r.Address(), err)
		var p *tx.Reply
		if r.Atyp == tx.ATYPIPv4 || r.Atyp == tx.ATYPDomain {
			p = tx.NewReply(tx.RepHostUnreachable, tx.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = tx.NewReply(tx.RepHostUnreachable, tx.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err = p.WriteTo(w); err != nil {
			log.E("svcsocks5: tcp: %s; write-to remote %s; err: %v", cid, r.Address(), err)
			return
		}
		return
	}

	var ok bool
	rc, ok = tc.(*net.TCPConn)
	if !ok {
		h.status = SKO
		err = errNotTcp
		return
	}
	laddr := rc.LocalAddr()
	if laddr == nil {
		log.W("svcsocks5: tcp: %s; err no local addr", cid, laddr)
		h.status = SKO
		err = errNoAddr
		return
	}

	a, addr, port, perr := tx.ParseAddress(laddr.String())
	if perr != nil {
		log.W("svcsocks5: tcp: %s; parse-addr err? %v", cid, err)
		var p *tx.Reply
		if r.Atyp == tx.ATYPIPv4 || r.Atyp == tx.ATYPDomain {
			p = tx.NewReply(tx.RepHostUnreachable, tx.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = tx.NewReply(tx.RepHostUnreachable, tx.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err = p.WriteTo(w); err != nil {
			log.E("svcsocks5: tcp: %s; write-to remote %s; err: %v", cid, r.Address(), err)
			return
		}
		err = perr
		return
	}

	p := tx.NewReply(tx.RepSuccess, a, addr, port)
	if _, err = p.WriteTo(w); err != nil {
		log.E("svcsocks5: tcp: %s; write-to remote %s; err: %v", cid, r.Address(), err)
		return
	}
	return
}

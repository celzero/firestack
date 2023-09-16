// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rnet

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	tx "github.com/txthinking/socks5"
)

var _ tx.Handler = (*socks5)(nil)

type socks5 struct {
	*tx.Server
	id     string
	url    string
	hdl    *socks5handler
	status int
}

type socks5handler struct {
	*tx.DefaultHandle
	px ipn.Proxy
}

func newSocks5Server(id, x string, ctl protect.Controller) (Server, error) {
	var host string
	var usr string
	var pwd string

	tx.Dial = protect.MakeNsXDial(ctl)

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
		DefaultHandle: &tx.DefaultHandle{},
	}
	server, _ := tx.NewClassicServer(host, remoteip, usr, pwd, tcptimeoutsec, udptimeoutsec)

	hasauth := len(usr) > 0 || len(pwd) > 0
	log.I("svcsocks5: new %s listening at %s; auth?", id, host, hasauth)
	return &socks5{
		Server: server,
		id:     id,
		url:    host,
		hdl:    hdl,
		status: SOK,
	}, nil
}

func (h *socks5) Hop(p ipn.Proxy) error {
	if p == nil {
		h.hdl.px = nil
		return nil
	}
	if h.status == END {
		log.D("svcsocks5: hop: %s not running", h.ID())
		return errServerEnd
	}
	h.hdl.px = p
	log.D("svchttp: hop: %s set to %s", h.ID(), p.GetAddr())
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
	h.status = SOK
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
func (h *socks5) TCPHandle(server *tx.Server, addr *net.TCPConn, req *tx.Request) error {
	px := h.hdl.px
	if px == nil {
		return h.hdl.TCPHandle(server, addr, req)
	}
	if px.Status() == ipn.END {
		return errProxyEnd
	}
	return h.tcphandle(server, addr, req)
}

// Implement tx.Handler
func (h *socks5) UDPHandle(server *tx.Server, addr *net.UDPAddr, pkt *tx.Datagram) error {
	px := h.hdl.px
	if px == nil {
		return h.hdl.UDPHandle(server, addr, pkt)
	}
	if px.Status() == ipn.END {
		return errProxyEnd
	}
	return h.udphandle(server, addr, pkt)
}

// Adopted from tx.DefaultHandle with the only change to use ipn.Proxy as the dialer
func (h *socks5) tcphandle(s *tx.Server, c *net.TCPConn, r *tx.Request) error {
	if r.Cmd == tx.CmdConnect {
		log.D("svcsocks5: proxy-tcp: %s; socks5-connect %s", h.ID(), r.Address())
		rc, err := h.Connect(r, c)
		if err != nil {
			h.status = SKO
			log.E("svcsocks5: proxy-tcp: %s; connect %s; err: %v", h.ID(), r.Address(), err)
			return err
		}
		defer rc.Close()

		go func() {
			bf := *core.Alloc()
			bf = bf[:cap(bf)]
			defer func() {
				core.Recycle(&bf)
			}()
			for {
				if s.TCPTimeout != 0 {
					ttl := time.Duration(s.TCPTimeout) * time.Second
					if err := rc.SetDeadline(time.Now().Add(ttl)); err != nil {
						log.E("svcsocks5: remote-tcp: %s; deadline %s; err: %v", h.ID(), r.Address(), err)
						return
					}
				}
				n, err := rc.Read(bf[:])
				if err != nil {
					log.E("svcsocks5: remote-tcp: %s; read %s; err: %v", h.ID(), rc.RemoteAddr(), err)
					return
				}
				if _, err := c.Write(bf[0:n]); err != nil {
					log.E("svcsocks5: local-tcp: %s; write %s; err: %v", h.ID(), c.LocalAddr(), err)
					return
				}
				log.V("svcsocks5: remote-tcp: %s; from: %s; %d bytes", h.ID(), r.Address(), n)
			}
		}()

		bf := *core.Alloc()
		bf = bf[:cap(bf)]
		defer func() {
			core.Recycle(&bf)
		}()
		for {
			if s.TCPTimeout != 0 {
				ttl := time.Duration(s.TCPTimeout) * time.Second
				if err := c.SetDeadline(time.Now().Add(ttl)); err != nil {
					return nil
				}
			}
			n, err := c.Read(bf[:])
			if err != nil {
				log.E("svcsocks5: local-tcp: %s; read %s; err: %v", h.ID(), c.LocalAddr(), err)
				return nil
			}
			if _, err := rc.Write(bf[0:n]); err != nil {
				log.E("svcsocks5: remote-tcp: %s; write %s; err: %v", h.ID(), r.Address(), err)
				return nil
			}
			log.V("svcsocks5: local-tcp: %s; to: %s; %d bytes", h.ID(), r.Address(), n)
		}
	}
	if r.Cmd == tx.CmdUDP {
		log.D("svcsocks5: proxy-tcp via udp: %s; socks5-tcp-udp %s", h.ID(), r.Address())
		caddr, err := r.UDP(c, s.ServerAddr)
		if err != nil {
			h.status = SKO
			return err
		}

		ch := make(chan byte)
		defer close(ch)

		s.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer s.AssociatedUDP.Delete(caddr.String())

		io.Copy(io.Discard, c)

		log.D("svcsocks: tcp: %s tcp that udp %s associated closed", h.ID(), caddr)
		return nil
	}
	return tx.ErrUnsupportCmd
}

func (h *socks5) udphandle(s *tx.Server, addr *net.UDPAddr, pkt *tx.Datagram) error {
	src := addr.String()
	var ch chan byte
	if s.LimitUDP {
		any, ok := s.AssociatedUDP.Get(src)
		if !ok {
			return fmt.Errorf("udp addr %s not associated with tcp", src)
		}
		ch = any.(chan byte)
	}
	send := func(ue *tx.UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("udp addr %s not associated with tcp", src)
		default:
			n, err := ue.RemoteConn.Write(data)
			if err != nil {
				log.E("svcsocks5: udp: %s; remote-write %s; err: %v", h.ID(), ue.RemoteConn.RemoteAddr(), err)
				return err
			}
			log.D("svcsocks5: udp: %s; data sent. client: %s server: %s remote: %s data: %d", h.ID(), ue.ClientAddr, ue.RemoteConn.LocalAddr(), ue.RemoteConn.RemoteAddr(), n)
		}
		return nil
	}

	dst := pkt.Address()
	var ue *tx.UDPExchange
	iue, ok := s.UDPExchanges.Get(src + dst)
	if ok {
		ue = iue.(*tx.UDPExchange)
		return send(ue, pkt.Data)
	}

	log.D("svcsocks5: udp: %s; dst %s", h.ID(), dst)
	uc, err := h.hdl.px.Dial("udp", dst)
	if err != nil {
		return err
	}

	rc, ok := uc.(*net.UDPConn)
	if !ok {
		return errNotUdp
	}

	ue = &tx.UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	log.D("svcsocks5: udp: %s; remote conn for client: %s server: %s remote: %s", h.ID(), addr, ue.RemoteConn.LocalAddr(), pkt.Address())
	if err := send(ue, pkt.Data); err != nil {
		log.E("svcsocks5: udp: %s; send pkt %d to remote: %s; err %v", h.ID(), len(pkt.Data), ue.RemoteConn.RemoteAddr(), err)
		ue.RemoteConn.Close()
		return err
	}
	s.UDPExchanges.Set(src+dst, ue, -1)

	go func(ue *tx.UDPExchange, dst string) {
		b := *core.AllocRegion(core.B16384)
		b = b[:cap(b)]
		defer func() {
			ue.RemoteConn.Close()
			core.Recycle(&b)
			s.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
		}()

		for {
			select {
			case <-ch:
				log.D("svcsocks5: udp: %s; tcp to udp addr %s associated closed", h.ID(), ue.ClientAddr)
				return
			default:
				if s.UDPTimeout != 0 {
					ttl := time.Duration(s.UDPTimeout) * time.Second
					if err := ue.RemoteConn.SetDeadline(time.Now().Add(ttl)); err != nil {
						log.E("svcsocks5: udp: %s; err? %v", h.ID(), err)
						return
					}
				}
				n, err := ue.RemoteConn.Read(b[:])
				if err != nil {
					log.E("svcsocks5: udp: %s; read err: %v", h.ID(), err)
					return
				}
				log.D("svcsocks5: udp: %s; got data; client: %s server: %s remote: %s data: %d", h.ID(), ue.ClientAddr, ue.RemoteConn.LocalAddr(), ue.RemoteConn.RemoteAddr(), n)
				a, addr, port, err := tx.ParseAddress(dst)
				if err != nil {
					log.E("svcsocks5: udp: %s; parse-addr err? %v", h.ID(), err)
					return
				}
				d1 := tx.NewDatagram(a, addr, port, b[0:n])
				if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
					log.E("svcsocks5: udp: %s; write err: %v", h.ID(), err)
					return
				}
				log.V("svcsocks5: udp: %s; data sent; client: %s server: %s remote: %s data: %#v %#v %#v %#v %#v %#d datagram address: %s", h.ID(), ue.ClientAddr.String(), ue.RemoteConn.LocalAddr(), ue.RemoteConn.RemoteAddr(), d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, len(d1.Data), d1.Address())
			}
		}
	}(ue, dst)
	return nil
}

func (h *socks5) Connect(r *tx.Request, w io.Writer) (*net.TCPConn, error) {
	log.D("svcsocks5: tcp: %s; dial", h.ID(), r.Address())

	tc, err := h.hdl.px.Dial("tcp", r.Address())
	if err != nil {
		h.status = SKO

		log.W("svcsocks5: tcp: %s; dial remote %s; err: %v", h.ID(), r.Address(), err)
		var p *tx.Reply
		if r.Atyp == tx.ATYPIPv4 || r.Atyp == tx.ATYPDomain {
			p = tx.NewReply(tx.RepHostUnreachable, tx.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = tx.NewReply(tx.RepHostUnreachable, tx.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err = p.WriteTo(w); err != nil {
			log.E("svcsocks5: tcp: %s; write-to remote %s; err: %v", h.ID(), r.Address(), err)
			return nil, err
		}
		return nil, err
	}

	rc, ok := tc.(*net.TCPConn)
	if !ok {
		h.status = SKO
		return nil, errNotTcp
	}

	a, addr, port, err := tx.ParseAddress(rc.LocalAddr().String())
	if err != nil {
		log.W("svcsocks5: tcp: %s; parse-addr err? %v", h.ID(), err)
		var p *tx.Reply
		if r.Atyp == tx.ATYPIPv4 || r.Atyp == tx.ATYPDomain {
			p = tx.NewReply(tx.RepHostUnreachable, tx.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = tx.NewReply(tx.RepHostUnreachable, tx.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			log.E("svcsocks5: tcp: %s; write-to remote %s; err: %v", h.ID(), r.Address(), err)
			return nil, err
		}
		return nil, err
	}

	p := tx.NewReply(tx.RepSuccess, a, addr, port)
	if _, err := p.WriteTo(w); err != nil {
		log.E("svcsocks5: tcp: %s; write-to remote %s; err: %v", h.ID(), r.Address(), err)
		return nil, err
	}
	return rc, nil
}

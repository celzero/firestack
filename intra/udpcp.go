// Copyright (c) 2024 RethinkDNS and its authors.

package intra

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

func (h *udpHandler) dnsOverride(conn core.UDPConn, addr *net.UDPAddr, query []byte) bool {
	// dst is nil if dns is to be overriden; see: h.Connect
	if !h.isDns(addr) {
		return false
	}
	// conn perhaps used for this dns query, unlikely to be used again.
	defer h.Close(conn)

	resp, err := h.resolver.Forward(query)
	if resp != nil {
		_, err = conn.WriteFrom(resp, addr)
	}
	if err != nil {
		log.W("udp: dns: query failed %v", err)
	}
	return true // handled
}

func (h *udpHandler) upload(c core.UDPConn, t *tracker) {
	// assign a big enough buffer since netstack does assemble fragmented packets
	// which could go as big as max-packet-size (65K?)
	// also: github.com/cloudflare/slirpnetstack/blob/41e49c3294/proxy.go#L73
	// and: github.com/cloudflare/slirpnetstack/blob/41e49c3294/proxy.go#L114
	// max: github.com/google/gvisor/blob/be6ffa78/pkg/tcpip/transport/udp/protocol.go#L43
	// though, we never expect to exceed mtu, so we can use a smaller buffer?
	// TODO: MTU
	bptr := core.Alloc()
	q := *bptr
	q = q[:cap(q)]
	defer func() {
		*bptr = q
		core.Recycle(bptr)
	}()
	for {
		if h.status == UDPEND {
			log.D("udp: handle-data: end")
			return
		}
		c.SetDeadline(time.Now().Add(udptimeout))
		// for ReadFrom; addr is gc.RemoteAddr() ie gc.LocalAddr()
		// github.com/google/gvisor/blob/be6ffa78e/pkg/tcpip/transport/udp/endpoint.go#L298
		if n, err := c.Read(q[:]); err == nil {
			// if using ReadFrom: who(10.111.222.3:17711)
			// who, _ := addr.(*net.UDPAddr)
			// dst(l:10.111.222.3:17711 / r:10.111.222.1:53)
			l := c.LocalAddr()
			r := c.RemoteAddr()
			// if who != nil && (who.String() != l.String())
			//	log.W("ns.udp.forwarder: MISMATCH expected-src(%v) => actual(l:%v)", who, l)

			log.V("ns.udp.forwarder: DATA src(%v) => dst(l:%v / r:%v)", l, r)

			dst, err := udpAddrFrom(r)
			if err != nil {
				log.E("udp: handle-data: failed to parse dst(%s); err(%v)", dst, err)
				return
			}

			if errh := h.ReceiveTo(c, q[:n], dst); errh != nil {
				c.Close()
				break
			}
		} else {
			// TODO: handle temporary errors?
			log.D("ns.udp.forwarder: DONE err(%v)", err)
			// leave gc open?
			break
		}
	}
}

// ReceiveTo is called when data arrives from conn (tun).
func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) (err error) {
	var next error = nil // ok to recv next packet
	nsladdr := conn.LocalAddr()
	nsraddr := conn.RemoteAddr()
	raddr := addr

	nat, _ := h.probe(conn)

	if nat == nil { // no nat
		s := fmt.Sprintf("udp: egress: no-op; closed? no nat(%v -> %v [%v])", nsladdr, raddr, nsraddr)
		log.W(s)
		return errors.New(s)
	}
	if !nat.connected() { // no nat conn; see h.Connect
		if h.dnsOverride(conn, addr, data) { // if dns request; handle it
			log.D("udp: egress: %s dns-op; dstaddr(%v) <- src(l:%v r:%v)", nat.ID, raddr, nsladdr, nsraddr)
			return nil
		}
		return fmt.Errorf("udp: egress: %s conn %v -> %v [%v] does not exist", nat.ID, nsladdr, raddr, nsraddr)
	}

	nat.Tx += int64(len(data))

	switch c := nat.dst.(type) {
	// net.UDPConn is both net.Conn and net.PacketConn; check net.Conn
	// first, as it denotes a connected socket which netstack also uses
	case net.Conn:
		c.SetDeadline(time.Now().Add(udptimeout))
		// c is already dialed-in to some addr in udpHandler.Connect
		_, err = c.Write(data)
	default:
		err = errUdpSetupConn
	}

	// is err recoverable?
	// ref: github.com/miekg/dns/blob/f8a185d39/server.go#L521
	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		nat.errcount += 1
		if !nat.ok() {
			log.W("udp: egress: %s too many errors(%d) for conn(l:%v -> r:%v [%v]) for uid %s", nat.ID, nat.errcount, nsladdr, raddr, nsraddr, nat.UID)
			return err
		} else {
			log.W("udp: egress: %s temporary error(%v) for conn(l:%v -> r:%v [%v]) for uid %s", nat.ID, err, nsladdr, raddr, nsraddr, nat.UID)
			return next
		}
	} else if err != nil {
		log.I("udp: egress: %s end splice (%v -> %v [%v]), forward udp for uid %s w err(%v)", nat.ID, conn.LocalAddr(), raddr, nsraddr, nat.UID, err)
		return err
	} else {
		nat.errcount = 0
	}

	log.I("udp: egress: %s conn(%v -> %v [%v]) / data(%d) for uid %s", nat.ID, nsladdr, raddr, nsraddr, len(data), nat.UID)
	return next
}

// download reads from nat.dst to masqurade-write it to core.UDPConn (tun)
func (h *udpHandler) download(conn core.UDPConn, nat *tracker) {
	defer func() {
		h.Close(conn)
	}()

	if ok := conn.Ready(); !ok {
		return
	}

	bptr := core.Alloc()
	buf := *bptr
	buf = buf[:cap(buf)]
	defer func() {
		*bptr = buf
		core.Recycle(bptr)
	}()

	var err error
	for {
		if h.status == UDPEND {
			log.D("udp: ingress: end", h.status)
			nat.done(errUdpEnd)
			return
		}
		if !nat.ok() {
			log.D("udp: ingress: %s too many errors (%v); latest(%v), closing", nat.ID, nat.errcount, err)
			nat.done(err) // err may be nil
			return
		}

		var n int
		var logaddr string
		var addr net.Addr
		// FIXME: ReadFrom seems to block for 50mins+ at times:
		// Cancel the goroutine in such cases and close the conns
		switch c := nat.dst.(type) { // assume nat.connected() == true
		// net.UDPConn is both net.Conn and net.PacketConn; check net.Conn
		// first, as it denotes a connected socket which netstack also uses
		case net.Conn:
			logaddr = conn2str(conn, c)
			log.D("udp: ingress: %s read (c) remote for %s", nat.ID, logaddr)

			c.SetDeadline(time.Now().Add(udptimeout)) // extend deadline
			// c is already dialed-in to some addr in udpHandler.Connect
			n, err = c.Read(buf[:])
		default:
			err = errUdpRead
		}

		// is err recoverable? github.com/miekg/dns/blob/f8a185d39/server.go#L521
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			nat.errcount += 1
			log.I("udp: ingress: %s [%s] temp err#%d(%v)", nat.ID, logaddr, nat.errcount, err)
			continue
		} else if err != nil {
			log.I("udp: ingress: %s [%s] err(%v)", nat.ID, logaddr, err)
			nat.done(err)
			return
		}

		var udpaddr *net.UDPAddr
		if addr != nil {
			udpaddr, _ = addr.(*net.UDPAddr)
		} else if nat.ip != nil {
			// overwrite source-addr as set in t.ip
			udpaddr = nat.ip
		}

		log.D("udp: ingress: %s data(%d) from remote(pc?%v/masq:%v) | addrs: %s", nat.ID, n, addr, udpaddr, logaddr)

		if udpaddr == nil {
			log.W("udp: ingress: %s unexpected! %s is not a udpaddr [%s]", nat.ID, addr, logaddr)
			n, err = conn.Write(buf) // writes buf to conn (tun)
		} else {
			n, err = conn.WriteFrom(buf[:n], udpaddr) // writes buf to conn (tun) with udpaddr as src
		}
		nat.Rx += int64(n) // rcvd (download) so far
		if err != nil {
			log.W("udp: ingress: %s failed write to tun (%s) from %s; err %v; %dsecs", nat.ID, logaddr, udpaddr, err, nat.Duration)
			// for half-open: nat.errcount += 1 and continue
			// otherwise: return and close conn
			nat.done(err)
			return
		} else {
			nat.elapsed() // time since last write
		}
	}
}

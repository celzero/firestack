// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
)

// pipe copies data from src to dst, and returns the number of bytes copied.
// Prefers src.WriteTo(dst) and dst.ReadFrom(src) if available.
// Otherwise, uses io.CopyBuffer, recycling buffers from global pool.
func pipe(dst io.Writer, src io.Reader) (int64, error) {
	if x, ok := src.(io.WriterTo); ok {
		return x.WriteTo(dst)
	} else if x, ok := dst.(io.ReaderFrom); ok {
		return x.ReadFrom(src)
	}
	bptr := core.AllocRegion(core.BMAX)
	b := *bptr
	b = b[:cap(b)]
	defer func() {
		*bptr = b
		core.Recycle(bptr)
	}()
	return io.CopyBuffer(dst, src, b)
}

// TODO: Propagate TCP RST using local.Abort(), on appropriate errors.
func upload(cid string, local net.Conn, remote net.Conn, ioch chan<- ioinfo) {
	ci := conn2str(local, remote)

	n, err := pipe(remote, local)
	log.D("intra: %s upload(%d) done(%v) b/w %s", cid, n, err, ci)

	pclose(local, "r")
	pclose(remote, "w")
	ioch <- ioinfo{n, err}
}

func download(cid string, local net.Conn, remote net.Conn) (n int64, err error) {
	ci := conn2str(local, remote)

	n, err = pipe(local, remote)
	log.D("intra: %s download(%d) done(%v) b/w %s", cid, n, err, ci)

	pclose(local, "w")
	pclose(remote, "r")
	return
}

// forward copies data between local and remote, and tracks the connection.
// It also sends a summary to the listener when done. Always called in a goroutine.
func forward(local net.Conn, remote net.Conn, t core.ConnMapper, l SocketListener, smm *SocketSummary) {
	cid := smm.ID

	t.Track(cid, local, remote)
	defer t.Untrack(cid)

	uploadch := make(chan ioinfo)

	var dbytes int64
	var derr error
	go upload(cid, local, remote, uploadch)
	dbytes, derr = download(cid, local, remote)

	upload := <-uploadch

	// remote conn could be dialed in to some proxy; and so,
	// its remote addr may not be the same as smm.Target
	smm.Rx = dbytes
	smm.Tx = upload.bytes

	smm.done(derr, upload.err)
	go sendNotif(l, smm)
}

// must always be called from a goroutine
func sendNotif(l SocketListener, s *SocketSummary) {
	if s == nil { // unlikely
		return
	}
	// sleep a bit to avoid scenario where kotlin-land
	// hasn't yet had the chance to persist info about
	// this conn (cid) to meaninfully process its summary
	time.Sleep(1 * time.Second)

	ok1 := l != nil      // likely due to bugs
	ok2 := len(s.ID) > 0 // likely due to bugs
	log.V("intra: end? sendNotif(%t,%t): %s", ok1, ok2, s.str())
	if ok1 && ok2 {
		l.OnSocketClosed(s) // s.Duration may be uninitialized (zero)
	}
}

func dnsOverride(r dnsx.Resolver, proto string, conn net.Conn, addr netip.AddrPort) bool {
	// addr with zone information removed; see: netip.ParseAddrPort which h.resolver relies on
	// addr2 := &net.TCPAddr{IP: addr.IP, Port: addr.Port}
	if r.IsDnsAddr(addr.String()) {
		// conn closed by the resolver
		r.Serve(proto, conn)
		return true
	}
	return false
}

// TODO: move this to ipn.Ground
func stall(m *core.ExpMap, k string) (secs uint32) {
	if n := m.Get(k); n <= 0 {
		secs = 0 // no stall
	} else if n > 30 {
		secs = 30 // max up to 30s
	} else if n < 5 {
		secs = (rand.Uint32() % 5) + 1 // up to 5s
	} else {
		secs = n
	}
	// track uid->target for n secs, or 30s if n is 0
	life30s := ((29 + secs) % 30) + 1
	newlife := time.Duration(life30s) * time.Second
	m.Set(k, newlife)
	return
}

func netipFrom(ip net.IP) *netip.Addr {
	if addr, ok := netip.AddrFromSlice(ip); ok {
		addr = addr.Unmap()
		return &addr
	}
	return nil
}

func oneRealIp(realips string, origipp netip.AddrPort) netip.AddrPort {
	if len(realips) <= 0 {
		return origipp
	}
	if first := makeIPPorts(realips, origipp, 1); len(first) > 0 {
		return first[0]
	}
	return origipp
}

func makeIPPorts(realips string, origipp netip.AddrPort, cap int) []netip.AddrPort {
	ips := strings.Split(realips, ",")
	if len(ips) <= 0 {
		return []netip.AddrPort{origipp}
	}
	if cap <= 0 || cap > len(ips) {
		cap = len(ips)
	}
	r := make([]netip.AddrPort, 0, cap)
	// override alg-ip with the first real-ip
	for _, v := range ips { // may contain unspecifed ips
		if len(r) >= cap {
			break
		}
		// len may be zero when realips is "," or ""
		if len(v) > 0 {
			ip, err := netip.ParseAddr(v)
			if err == nil && ip.IsValid() && !ip.IsUnspecified() {
				r = append(r, netip.AddrPortFrom(ip, origipp.Port()))
			}
		}
	}

	if len(r) > 0 {
		rand.Shuffle(len(r), func(i, j int) {
			r[i], r[j] = r[j], r[i]
		})
		return r
	}

	return []netip.AddrPort{origipp}
}

func undoAlg(r dnsx.Resolver, algip netip.Addr) (realips, domains, probableDomains, blocklists string) {
	force := true // force PTR resolution
	if gw := r.Gateway(); !algip.IsUnspecified() && algip.IsValid() && gw != nil {
		dst := algip.AsSlice()
		domains = gw.PTR(dst, !force)
		if len(domains) <= 0 {
			probableDomains = gw.PTR(dst, force)
		}
		realips = gw.X(dst)
		blocklists = gw.RDNSBL(dst)
	} else {
		log.W("alg: undoAlg: no gw(%t) or dst(%v) or alg-ip(%s)", gw == nil, algip, algip)
	}
	return
}

// returns proxy-id, conn-id, user-id
func splitCidPidUid(decision *Mark) (cid, pid, uid string) {
	if decision == nil {
		return
	}
	return decision.CID, decision.PID, decision.UID
}

func ipp(addr net.Addr) (netip.AddrPort, error) {
	var zeroaddr = netip.AddrPort{}
	if addr == nil {
		return zeroaddr, errors.New("nil addr")
	}
	return netip.ParseAddrPort(addr.String())
}

func addr2ip(a net.Addr) string {
	if a == nil {
		return ""
	}
	switch x := a.(type) {
	case *net.TCPAddr:
		return x.IP.String()
	case *net.UDPAddr:
		return x.IP.String()
	case *net.IPAddr:
		return x.IP.String()
	case *net.IPNet:
		return x.IP.String()
	}
	if b, err := netip.ParseAddrPort(a.String()); err == nil {
		return b.Addr().String()
	}
	return ""
}

func conn2str(a net.Conn, b net.Conn) string {
	ar := a.RemoteAddr()
	br := b.RemoteAddr()
	al := a.LocalAddr()
	bl := b.LocalAddr()
	return fmt.Sprintf("a(%v->%v) => b(%v<-%v)", al, ar, bl, br)
}

func closeconns(cm core.ConnMapper, cids []string) (closed []string) {
	if len(cids) <= 0 {
		closed = cm.Clear()
	} else {
		closed = cm.UntrackBatch(cids)
	}

	log.I("intra: closed %d/%d", len(closed), len(cids))
	return closed
}

func clos(c ...net.Conn) {
	for _, x := range c {
		if x != nil {
			x.Close()
		}
	}
}

func pclose(c io.Closer, a string) {
	if c == nil {
		return
	}
	if a == "rw" {
		c.Close()
		return
	}
	switch x := c.(type) {
	case core.TCPConn: // net.TCPConn confirms to core.TCPConn
		if a == "r" {
			x.CloseRead()
		} else if a == "w" {
			x.CloseWrite()
		} else { // == "rw"
			x.Close()
		}
	case core.UDPConn:
		x.Close()
	case io.Closer:
		x.Close()
	}
}

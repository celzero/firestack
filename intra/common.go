// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
)

const smmchSize = 24

// immediate is the wait time before sending a summary to the listener.
var immediate = time.Duration(0)

var (
	errNoAddr = errors.New("nil addr")
)

// TODO: Propagate TCP RST using local.Abort(), on appropriate errors.
func upload(cid string, local net.Conn, remote net.Conn, ioch chan<- ioinfo) {
	defer core.Recover(core.Exit11, "c.upload: "+cid)

	ci := conn2str(local, remote)

	n, err := core.Pipe(remote, local)
	log.D("intra: %s upload(%d) done(%v) b/w %s", cid, n, err, ci)

	core.CloseOp(local, core.CopR)
	core.CloseOp(remote, core.CopW)
	ioch <- ioinfo{n, err}
}

func download(cid string, local net.Conn, remote net.Conn) (n int64, err error) {
	ci := conn2str(local, remote)

	n, err = core.Pipe(local, remote)
	log.D("intra: %s download(%d) done(%v) b/w %s", cid, n, err, ci)

	core.CloseOp(local, core.CopW)
	core.CloseOp(remote, core.CopR)
	return
}

// forward copies data between local and remote, and tracks the connection.
// It also sends a summary to the listener when done. Always called in a goroutine.
func forward(local, remote net.Conn, ch chan *SocketSummary, done chan struct{}, smm *SocketSummary) {
	cid := smm.ID

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

	queueSummary(ch, done, smm.done(derr, upload.err))
}

func queueSummary(ch chan<- *SocketSummary, done <-chan struct{}, s *SocketSummary) {
	if s == nil {
		return
	}

	// go.dev/play/p/AXDdhcMu2w_k
	// even though channel done is always closed before ch, we still
	// see panic from the select statement writing to ch; and hence
	// the need to have this nested select statement.

	log.VV("intra: queueSummary: over %x %x %s", ch, done, s.ID)
	select {
	case <-done:
		log.D("intra: queueSummary: end: %s", s.str())
	default:
		select {
		case <-done:
		case ch <- s:
		default:
			log.W("intra: sendSummary: dropped: %s", s.str())
		}
	}
}

// must be called from a goroutine; loops reading from ch until done is closed.
func sendSummary(ch chan *SocketSummary, done chan struct{}, l SocketListener) {
	defer core.Recover(core.DontExit, "c.sendSummary")

	noch := ch == nil
	notok := l == nil || core.IsNil(l)
	if noch || notok {
		log.W("intra: sendSummary: nil ch(%t) or l(%t)", noch, notok)
		return
	}

	for {
		select {
		case <-done:
			return
		case s := <-ch:
			if s != nil && len(s.ID) > 0 {
				sendNotif(l, s, immediate)
			}
		}
	}
}

func sendNotif(l SocketListener, s *SocketSummary, after time.Duration) {
	defer core.Recover(core.DontExit, "c.sendNotif: "+s.ID)

	if after > 0 {
		// sleep a bit to avoid scenario where kotlin-land
		// hasn't yet had the chance to persist info about
		// this conn (cid) to meaninfully process its summary
		time.Sleep(after)
	}

	log.VV("intra: end? sendNotif: %s", s.str())
	l.OnSocketClosed(s) // s.Duration may be uninitialized (zero)
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
	use4 := dialers.Use4()
	use6 := dialers.Use6()

	ips := strings.Split(realips, ",")
	if len(ips) <= 0 {
		log.VV("intra: makeIPPorts(v4? %t, v6? %t): no realips; out: %s", use4, use6, origipp)
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
		if len(v) > 0 { // len may be zero when realips is "," or ""
			ip, err := netip.ParseAddr(v)
			if err == nil && ip.IsValid() && !ip.IsUnspecified() {
				r = append(r, netip.AddrPortFrom(ip, origipp.Port()))
			} // else: discard ip
		} // else: next v
	}

	log.VV("intra: makeIPPorts(v4? %t, v6? %t); tot: %d; in: %v, out: %v", use4, use6, len(ips), ips, r)

	if len(r) > 0 {
		rand.Shuffle(len(r), func(i, j int) {
			r[i], r[j] = r[j], r[i]
		})
		return r
	}

	log.W("intra: makeIPPorts(v4? %t, v6? %t): all: %d; out: %s", use4, use6, len(ips), origipp)
	return []netip.AddrPort{origipp}
}

func undoAlg(r dnsx.Resolver, algip netip.Addr) (realips, domains, probableDomains, blocklists string) {
	force := true // force PTR resolution
	if gw := r.Gateway(); !algip.IsUnspecified() && algip.IsValid() && gw != nil {
		domains = gw.PTR(algip, !force)
		if len(domains) <= 0 {
			probableDomains = gw.PTR(algip, force)
		}
		// prevent scenarios where the tunnel only has v4 (or v6) routes and
		// all the routing decisions by listener.Flow() are made based on those routes
		// but we end up dailing into a v6 (or v4) address (which was unaccounted for).
		// Dialing into v6 (or v4) address may succeed in such scenarios thereby
		// resulting in a perceived "leak".
		realips = filterFamilyForDialing(gw.X(algip))
		blocklists = gw.RDNSBL(algip)
	} else {
		log.W("alg: undoAlg: no gw(%t) or dst(%v)", gw == nil, algip)
	}
	return
}

// filterFamilyForDialing filters out invalid IPs and IPs that are not
// of the family that the dialer is configured to use.
func filterFamilyForDialing(ipcsv string) string {
	if len(ipcsv) <= 0 {
		return ipcsv
	}
	// assume ipv4 is available on ipv6-only network by the way of
	// any of the 4to6 mechanisms like 464Xlat, DNS64/NAT64, Teredo etc.
	fallback := false
	ips := strings.Split(ipcsv, ",")
	use4 := dialers.Use4()
	use6 := dialers.Use6()
	var filtered, unfiltered, invalids []string
	for _, v := range ips {
		if len(v) <= 0 {
			continue
		}
		ip, err := netip.ParseAddr(v)
		if err == nil && ip.IsValid() {
			// always include unspecified IPs as it is used by the client
			// to make block/no-block decisions
			if ip.IsUnspecified() || use4 && ip.Is4() || use6 && ip.Is6() {
				filtered = append(filtered, v)
			} else {
				unfiltered = append(unfiltered, v)
			}
		} else { // else: discard ip
			invalids = append(invalids, v)
		}
	}
	logger := log.VV
	if len(filtered) <= 0 {
		fallback = true
		filtered = unfiltered
		unfiltered = nil
		logger = log.W
	}
	logger("intra: filterFamily(v4? %t, v6? %t, fallback? %t): filtered: %d/%d; in: %v, out: %v, ignored: %v + %v", use4, use6, fallback, len(filtered), len(ips), ips, filtered, unfiltered, invalids)
	return strings.Join(filtered, ",")
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
	if addr == nil || core.IsNil(addr) {
		return zeroaddr, errNoAddr
	}
	return netip.ParseAddrPort(addr.String())
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
	core.CloseConn(c...)
}

// zeroListener is a no-op implementation of SocketListener.
type zeroListener struct{}

var _ SocketListener = (*zeroListener)(nil)

func (*zeroListener) Flow(_, _ int32, _, _, _, _, _, _ string) *Mark { return nil }
func (*zeroListener) OnSocketClosed(*SocketSummary)                  {}

var nooplistener = new(zeroListener)

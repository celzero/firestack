// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/netstat"
	"github.com/celzero/firestack/intra/settings"
)

const (
	smmchSize           = 24
	UNKNOWN_UID         = -1
	UNKNOWN_UID_STR     = "-1"
	UNSUPPORTED_NETWORK = -1
)

const (
	HDLOK = iota
	HDLEND
)

var (
	anyaddr4 = netip.IPv4Unspecified()
	anyaddr6 = netip.IPv6Unspecified()
)

// immediate is the wait time before sending a summary to the listener.
var immediate = time.Duration(0)

// zeroListener is a no-op implementation of SocketListener.
type zeroListener struct{}

var _ SocketListener = (*zeroListener)(nil)

func (*zeroListener) Preflow(_, _ int32, _, _, _ string) *PreMark    { return nil }
func (*zeroListener) Flow(_, _ int32, _, _, _, _, _, _ string) *Mark { return nil }
func (*zeroListener) Inflow(_, _ int32, _, _ string) *Mark           { return nil }
func (*zeroListener) OnSocketClosed(*SocketSummary)                  {}

var nooplistener = new(zeroListener)

type baseHandler struct {
	proto string // tcp, udp, icmp
	ctx   context.Context

	tunMode  *settings.TunMode
	resolver dnsx.Resolver // dns resolver to forward queries to
	smmch    chan *SocketSummary
	listener SocketListener // listener for socket summaries

	conntracker core.ConnMapper              // connid -> [local,remote]
	fwtracker   *core.ExpMap[string, string] // uid+dst(domainOrIP) -> blockSecs

	once sync.Once

	// fields below are mutable

	status *core.Volatile[int] // status of this handler
}

var _ netstack.GBaseConnHandler = (*baseHandler)(nil)

func newBaseHandler(pctx context.Context, proto string, r dnsx.Resolver, tm *settings.TunMode, l SocketListener) *baseHandler {
	h := &baseHandler{
		ctx:         pctx,
		proto:       proto,
		tunMode:     tm,
		resolver:    r,
		smmch:       make(chan *SocketSummary, smmchSize),
		listener:    l,
		fwtracker:   core.NewExpiringMap(pctx),
		conntracker: core.NewConnMap(),
		status:      core.NewVolatile(HDLOK),
	}
	context.AfterFunc(pctx, h.End)
	return h
}

// to is the local address, from is the remote address.
func (h *baseHandler) onInflow(to, from netip.AddrPort) (fm *Mark) {
	blockmode := h.tunMode.BlockMode.Load()
	fm = optionsBlock
	// BlockModeNone returns false, BlockModeSink returns true
	if blockmode == settings.BlockModeSink {
		return // blocks everything
	} // else: BlockModeNone|BlockModeFilter|BlockModeFilterProc

	uid := UNKNOWN_UID  // todo: uid only known on egress?
	nn := ntoa(h.proto) // -1 unsupported

	// inflow does not go through nat/alg/dns/proxy
	fm, ok := core.Grx(h.proto+".inflow", func(_ context.Context) (*Mark, error) {
		return h.listener.Inflow(nn, int32(uid), to.String(), from.String()), nil
	}, onFlowTimeout)

	if !ok || fm == nil {
		fm = optionsBlock // fail-safe: block everything
		log.E("inFlow: %s: timeout %v <= %v", h.proto, to, from)
		return
	}
	// todo: assert fm.PID == ipn.Ingress or ipn.Block
	return
}

// onFlow calls listener.Flow to determine egress rules and routes; thread-safe.
func (h *baseHandler) onFlow(localaddr, target netip.AddrPort) (fm *Mark, undidAlg bool, ips, doms string) {
	blockmode := h.tunMode.BlockMode.Load()
	fm = optionsBlock
	// BlockModeNone returns false, BlockModeSink returns true
	if blockmode == settings.BlockModeSink {
		return // blocks
	} else if blockmode == settings.BlockModeNone {
		fm = optionsBase
	} // else: BlockModeFilter|BlockModeFilterProc

	// Implicit: BlockModeFilter or BlockModeFilterProc
	uid := UNKNOWN_UID
	if blockmode == settings.BlockModeFilterProc {
		procEntry := netstat.FindProcNetEntry(h.proto, localaddr, target)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	network := h.proto
	if network == "icmp" && target.Addr().Is6() {
		network = "icmp6"
	}
	var proto int32 = ntoa(network) // -1 unsupported

	src := localaddr.String()
	dst := target.String()

	var pdoms, blocklists string
	var pre *PreMark
	var ok bool

	// alg happens after nat64, and so, alg knows nat-ed ips
	// that is, realips are un-nated
	undidAlg, ips, doms, pdoms, blocklists = h.undoAlg(target.Addr())
	hasOldIPs := len(ips) > 0
	if undidAlg && !hasOldIPs {
		pre, ok = core.Grx(h.proto+".preflow", func(_ context.Context) (*PreMark, error) {
			return h.listener.Preflow(proto, int32(uid), src, dst, doms), nil
		}, onFlowTimeout)

		hasNewIPs := false
		hasPre := pre != nil && len(pre.TIDCSV) > 0
		if ok && hasPre {
			if newuid, err := strconv.Atoi(pre.UID); err == nil {
				uid = newuid
			} else {
				log.W("onFlow: %s preflow: invalid uid %s; using %d, err? %v",
					h.proto, pre.UID, uid, err)
			}
			// empty pre.TIDCSV will result in len(tids) == 1
			// go.dev/play/p/67cd88Y1lUE
			tids := strings.Split(pre.TIDCSV, ",")
			for _, d := range strings.Split(doms, ",") {
				if len(d) <= 0 {
					log.V("onFlow: %s preflow: empty domain in %v from %v => %v for %s; skip!",
						h.proto, doms, src, target, pre.UID)
					continue
				}
				// ResolveOn will use dnsx.Default if TID is empty
				// see: dns53.ipmapper:queryIP & dnsx.transport:Lookup
				newips, err := dialers.ResolveOn(d, tids...)
				hasNewIPs = err == nil && len(newips) > 0
				if hasNewIPs { // fetch alg result if resolve succeeded
					_, ips, doms, pdoms, blocklists = h.undoAlg(target.Addr())
					break
				} // else: either no known transport or preflow failed
			}
		} // else: either no known transport or preflow failed

		if !ok || !hasPre || !hasNewIPs {
			log.W("onFlow: %s alg, but no preflow? %t / %t, ips? %t for %s over %s; block!",
				h.proto, ok, hasPre, hasNewIPs, pre.UID, pre.TIDCSV)
			// either optionsBase (BlockModeNone) or optionsBlock
			return fm, undidAlg, "", ""
		} // else: if we've got target and/or old ips, dial them
	} else {
		log.D("onFlow: %s noalg? %t or hasips? %t", h.proto, undidAlg, hasOldIPs)
	}

	if len(ips) <= 0 || len(doms) <= 0 {
		log.D("onFlow: %s no realips(%s) or domains(%s + %s), for src=%s dst=%s",
			h.proto, ips, doms, pdoms, localaddr, target)
	}

	fm, ok = core.Grx(h.proto+".flow", func(_ context.Context) (*Mark, error) {
		return h.listener.Flow(proto, int32(uid), src, dst, ips, doms, pdoms, blocklists), nil
	}, onFlowTimeout)

	if fm == nil || !ok { // zeroListener returns nil
		log.W("onFlow: %s empty res or on flow timeout %t; block!", h.proto, ok)
		fm = optionsBlock
	} else if len(fm.PID) <= 0 {
		log.E("onFlow: %s no pid from kt; exit!", h.proto)
		fm.PID = ipn.Exit
	}

	return
}

// forward copies data between local and remote, and tracks the connection.
// It also sends a summary to the listener when done. Always called in a goroutine.
func (h *baseHandler) forward(local, remote net.Conn, smm *SocketSummary) {
	cid := smm.ID
	uid := smm.UID
	via := smm.Proto + ":" + smm.PID

	tup := conn2str(local, remote)

	log.I("%s: new conn %s via proxy(%s); %s for %s",
		h.proto, cid, via, tup, uid)

	h.conntracker.Track(cid, local, remote)
	defer h.conntracker.Untrack(cid)

	uploadch := make(chan ioinfo)

	go upload(cid, via, local, remote, uploadch)
	dbytes, derr := download(cid, via, local, remote)

	upload := <-uploadch

	// remote conn could be dialed in to some proxy; and so,
	// its remote addr may not be the same as smm.Target
	smm.Rx = dbytes
	smm.Tx = upload.bytes

	h.queueSummary(smm.done(derr, upload.err))
}

func (h *baseHandler) queueSummary(s *SocketSummary) {
	if s == nil {
		return
	}

	// go.dev/play/p/AXDdhcMu2w_k
	// even though channel done is always closed before ch, we still
	// see panic from the select statement writing to ch; and hence
	// the need to have this nested select statement.

	log.VV("%s: queueSummary: %x %x %s", h.proto, h.smmch, h.ctx, s.ID)
	select {
	case <-h.ctx.Done():
		log.D("%s: queueSummary: end: %s", h.proto, s.str())
	default:
		select {
		case <-h.ctx.Done():
		case h.smmch <- s:
		default:
			log.W("%s: sendSummary: dropped: %s", h.proto, s.str())
		}
	}
}

// must be called from a goroutine; loops reading from ch until done is closed.
func (h *baseHandler) processSummaries() {
	defer core.Recover(core.DontExit, "c.sendSummary")

	for {
		select {
		case <-h.ctx.Done():
			return
		case s := <-h.smmch:
			if s != nil && len(s.ID) > 0 {
				h.sendSummary(s, immediate)
			}
		}
	}
}

func (h *baseHandler) sendSummary(s *SocketSummary, after time.Duration) {
	defer core.Recover(core.DontExit, "c.sendNotif: "+s.ID)

	if after > 0 {
		// sleep a bit to avoid scenario where kotlin-land
		// hasn't yet had the chance to persist info about
		// this conn (cid) to meaninfully process its summary
		time.Sleep(after)
	}

	log.VV("%s: end? sendNotif: %s", h.proto, s.str())
	h.listener.OnSocketClosed(s) // s.Duration may be uninitialized (zero)
}

// OpenConns implements netstack.GBaseConnHandler
func (h *baseHandler) OpenConns() string {
	return fmt.Sprintf("%d | %s", h.conntracker.Len()/2, h.conntracker.String())
}

// CloseConns implements netstack.GBaseConnHandler
func (h *baseHandler) CloseConns(cids []string) (closed []string) {
	if len(cids) <= 0 {
		closed = h.conntracker.Clear()
	} else {
		closed = h.conntracker.UntrackBatch(cids)
	}

	log.I("%s: closed %d/%d", h.proto, len(closed), len(cids))
	return closed
}

// TODO: move this to ipn.Block
func (h *baseHandler) stall(k string) (secs uint32) {
	if n := h.fwtracker.Get(k); n <= 0 {
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
	h.fwtracker.Set(k, newlife)
	if secs > 0 {
		w := time.Duration(secs) * time.Second
		time.Sleep(w)
	}
	return
}

func (h *baseHandler) dnsOverride(conn net.Conn, addr netip.AddrPort) bool {
	// addr with zone information removed; see: netip.ParseAddrPort which h.resolver relies on
	// addr2 := &net.TCPAddr{IP: addr.IP, Port: addr.Port}
	if addr.IsValid() && h.resolver.IsDnsAddr(addr) {
		// conn closed by the resolver
		h.resolver.Serve(h.proto, conn)
		return true
	}
	return false
}

// End implements netstack.GBaseConnHandler
func (h *baseHandler) End() {
	h.once.Do(func() {
		h.CloseConns(nil)
		h.status.Store(HDLEND)
		close(h.smmch) // close listener chan
		log.I("%s: handler end %x %x", h.proto, h.ctx, h.smmch)
	})
}

// TODO: Propagate TCP RST using local.Abort(), on appropriate errors.
func upload(cid, proto string, local net.Conn, remote net.Conn, ioch chan<- ioinfo) {
	defer core.Recover(core.Exit11, "c.upload: "+cid)

	ci := conn2str(local, remote)

	n, err := core.Pipe(remote, local)
	log.D("%s: %s upload(%d) done(%v) b/w %s", proto, cid, n, err, ci)

	core.CloseOp(local, core.CopR)
	core.CloseOp(remote, core.CopW)
	ioch <- ioinfo{n, err}
}

func download(cid, proto string, local net.Conn, remote net.Conn) (n int64, err error) {
	ci := conn2str(local, remote)

	n, err = core.Pipe(local, remote)
	log.D("%s: %s download(%d) done(%v) b/w %s", proto, cid, n, err, ci)

	core.CloseOp(local, core.CopW)
	core.CloseOp(remote, core.CopR)
	return
}

func oneRealIPPort(realips string, origipp netip.AddrPort) netip.AddrPort {
	if len(realips) <= 0 {
		return origipp
	}
	if first := makeIPPorts(realips, origipp, 1); len(first) > 0 {
		return first[0]
	}
	return origipp
}

func makeAnyAddrPort(origipp netip.AddrPort) netip.AddrPort {
	if !origipp.IsValid() {
		return origipp
	}
	if origipp.Addr().Is4() {
		return netip.AddrPortFrom(anyaddr4, origipp.Port())
	}
	return netip.AddrPortFrom(anyaddr6, origipp.Port())
}

// makeIPPorts returns a slice of valid, non-zero at most cap AddrPorts.
// The first element may be origipp AddrPort, if realips is empty or contains only unspecified IPs.
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

	log.VV("intra: makeIPPorts(v4? %t, v6? %t): using origip; all: %d; out: %s",
		use4, use6, len(ips), origipp)
	return []netip.AddrPort{origipp}
}

// algip may or may not be an actual alg ip.
func (h *baseHandler) undoAlg(algip netip.Addr) (undidAlg bool, realips, domains, probableDomains, blocklists string) {
	r := h.resolver
	didForce := false
	forcePTR := true // force PTR resolution?
	if gw := r.Gateway(); !algip.IsUnspecified() && algip.IsValid() && gw != nil {
		domains, didForce = gw.PTR(algip, !forcePTR)
		if !didForce && len(domains) <= 0 {
			probableDomains, _ = gw.PTR(algip, forcePTR)
		}
		// prevent scenarios where the tunnel only has v4 (or v6) routes and
		// all the routing decisions by listener.Flow() are made based on those routes
		// but we end up dailing into a v6 (or v4) address (which was unaccounted for).
		// Dialing into v6 (or v4) address may succeed in such scenarios thereby
		// resulting in a perceived "leak".
		realips, undidAlg = gw.X(algip)
		realips = filterFamilyForDialing(realips)
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
	// fail open: if no ipv4 then fallback to ipv6, and vice-versa.
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

func conn2str(a net.Conn, b net.Conn) string {
	ar := a.RemoteAddr()
	br := b.RemoteAddr()
	al := a.LocalAddr()
	bl := b.LocalAddr()
	return fmt.Sprintf("a(%v->%v) => b(%v<-%v)", al, ar, bl, br)
}

func clos(c ...core.MinConn) {
	core.CloseConn(c...)
}

func ntoa(n string) int32 {
	switch n {
	case "udp", "udp6", "udp4":
		return 17
	case "tcp", "tcp6", "tcp4":
		return 6
	case "icmp", "icmp4":
		return 1
	case "icmp6":
		return 58
	}
	return UNSUPPORTED_NETWORK
}

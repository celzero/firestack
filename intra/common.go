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

	"slices"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/netstat"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

const (
	smmchSize           = 64
	UNKNOWN_UID         = core.UNKNOWN_UID
	UNKNOWN_UID_STR     = core.UNKNOWN_UID_STR
	SELF_UID            = protect.UidSelf
	UNSUPPORTED_NETWORK = core.UNSUPPORTED_NETWORK
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

	resolver dnsx.Resolver     // dns resolver to forward queries to
	prox     ipn.ProxyProvider // proxy provider
	smmch    chan *SocketSummary
	listener SocketListener // listener for socket summaries

	conntracker core.ConnMapper              // connid -> [local,remote]
	fwtracker   *core.ExpMap[string, string] // uid+dst(domainOrIP) -> blockSecs

	once sync.Once

	// fields below are mutable

	status *core.Volatile[int] // status of this handler
}

var _ netstack.GBaseConnHandler = (*baseHandler)(nil)

func newBaseHandler(pctx context.Context, proto string, r dnsx.Resolver, px ipn.ProxyProvider, l SocketListener) *baseHandler {
	h := &baseHandler{
		ctx:         pctx,
		proto:       proto,
		resolver:    r,
		prox:        px,
		smmch:       make(chan *SocketSummary, smmchSize),
		listener:    l,
		fwtracker:   core.NewExpiringMap[string, string](pctx),
		conntracker: core.NewConnMap(),
		status:      core.NewVolatile(HDLOK),
	}
	context.AfterFunc(pctx, h.End)
	return h
}

// to is the local address, from is the remote address.
func (h *baseHandler) onInflow(to, from netip.AddrPort) (fm *Mark) {
	blockmode := settings.BlockMode.Load()
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
		log.E("com: %s: inFlow: timeout %v <= %v", h.proto, to, from)
		return
	}
	// todo: assert fm.PID == ipn.Ingress or ipn.Block
	return
}

// onFlow calls listener.Flow to determine egress rules and routes; thread-safe.
func (h *baseHandler) onFlow(localaddr, target netip.AddrPort) (fm *Mark, undidAlg bool, ips, doms string) {
	blockmode := settings.BlockMode.Load()
	fm = optionsBlock
	// BlockModeNone returns false, BlockModeSink returns true
	if blockmode == settings.BlockModeSink {
		return // blocks
	} else if blockmode == settings.BlockModeNone {
		fm = optionsExit
	} // else: BlockModeFilter|BlockModeFilterProc

	// Implicit: BlockModeFilter or BlockModeFilterProc
	uid := UNKNOWN_UID
	preuid := UNKNOWN_UID_STR
	if blockmode == settings.BlockModeFilterProc {
		procEntry := netstat.FindProcNetEntry(h.proto, localaddr, target)
		if procEntry != nil {
			uid = procEntry.UserID
			preuid = strconv.Itoa(uid)
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

	pre, _ := core.Grx(h.proto+".preflow", func(_ context.Context) (*PreMark, error) {
		return h.listener.Preflow(proto, int32(uid), src, dst, doms), nil
	}, onFlowTimeout)

	hasPre := pre != nil
	if hasPre && pre != nil /*nilaway*/ && len(pre.UID) > 0 {
		if c, cerr := strconv.Atoi(pre.UID); cerr == nil {
			uid = c
			// alg.go, for its per-uid cache, uses a special UID to denote
			// our own process (protect.UidSelf) and so make sure to use it.
			if pre.IsUidSelf {
				preuid = SELF_UID
			} else {
				preuid = pre.UID
			}
		} else {
			log.W("com: %s: onFlow: preflow: uid %s is not a number; use %s", h.proto, pre.UID, uid)
		}
	}

	// alg happens after nat64, and so, alg knows nat-ed ips and un-nats them;
	// that is, real ips ("ips") are already un-nated where applicable.
	undidAlg, ips, doms, pdoms, blocklists = h.undoAlg(target.Addr(), preuid)
	hasOldIPs := len(ips) > 0
	if undidAlg && !hasOldIPs {
		hasNewIPs := false
		if hasPre {
			for d := range strings.SplitSeq(doms, ",") {
				if len(d) <= 0 {
					log.V("com: %s: onFlow: preflow: empty domain in %v from %v => %v for %s; skip!",
						h.proto, doms, src, target, preuid)
					continue
				}
				newips, err := dialers.ResolveFor(d, preuid)
				hasNewIPs = err == nil && len(newips) > 0
				if hasNewIPs { // already unalg'd by ipmapper
					// _, ips, doms, pdoms, blocklists = h.undoAlg(target.Addr())
					ips = dnsx.Netip2Csv(newips)
					break
				} // else: either no known transport or preflow failed
			}
		} // else: either no known transport or preflow failed

		if !hasPre || !hasNewIPs {
			log.E("com: %s: onFlow: alg, preflow? %t, ips? %t for %v; uid: %s; block!",
				h.proto, hasPre, hasNewIPs, doms, pre)
			// either optionsBase (BlockModeNone) or optionsBlock
			return fm, undidAlg, "", ""
		} // else: if we've got target and/or old ips, dial them
	} else {
		log.D("com: %s: onFlow: noalg? %t or hasips? %t", h.proto, !undidAlg, hasOldIPs)
	}

	if len(ips) <= 0 || len(doms) <= 0 {
		log.D("com: %s: onFlow: no realips(%s) or domains(%s + %s), for src=%s dst=%s",
			h.proto, ips, doms, pdoms, localaddr, target)
	}

	fm, ok := core.Grx(h.proto+".flow", func(_ context.Context) (*Mark, error) {
		return h.listener.Flow(proto, int32(uid), src, dst, ips, doms, pdoms, blocklists), nil
	}, onFlowTimeout)

	if fm == nil || !ok { // zeroListener returns nil
		log.W("com: %s: onFlow: empty res or on flow timeout %t; block!", h.proto, ok)
		fm = optionsBlock
	} else if len(fm.PIDCSV) <= 0 {
		if preuid == SELF_UID {
			fm.PIDCSV = ipn.Exit
		} else if h.prox.AutoActive() {
			fm.PIDCSV = ipn.Auto
		} else {
			fm.PIDCSV = ipn.Exit
		}
		log.E("com: %s: onFlow: missing proxyid for preuid %s (%s => %s) from kt (alg: %v + %v); %s!",
			h.proto, preuid, src, dst, ips, doms, fm.PIDCSV)
	}
	if preuid == SELF_UID && !ipn.IsAnyLocalProxy(strings.Split(fm.PIDCSV, ",")...) {
		egress := ipn.Exit
		if h.resolver.IsDnsAddr(target) {
			egress = ipn.Base // see: udp.go:dnsOverride
		}
		log.W("com: %s: onFlow: preflow: preuid %s (%s => %s) is rethink! override %s to %s!",
			h.proto, preuid, src, dst, fm.PIDCSV, egress)
		fm.PIDCSV = egress
	}

	return
}

// forward copies data between local and remote, and tracks the connection.
// It also sends a summary to the listener when done. Always called in a goroutine.
func (h *baseHandler) forward(local, remote net.Conn, smm *SocketSummary) {
	cid := smm.ID
	uid := smm.UID
	pid := smm.PID
	via := strings.Join([]string{smm.Proto, smm.PID, smm.RPID}, ":")

	tup := conn2str(local, remote)

	h.conntracker.Track(cid, uid, pid, local, remote)
	defer h.conntracker.Untrack(cid)

	isrwext := false
	iszerodeadline := false
	withsockopt := false
	// enable core.Pipe (sendfile/zero-copy) optimizations on TCP if
	// read & write deadlines are not set (as in rwext is effectively
	// a no-op) by unwrapping the underlying remote conn from rwext.
	if r, ok := remote.(rwext); ok {
		isrwext = true
		if r.IsZeroDeadline() {
			iszerodeadline = true
			remote = r.Unwrap()
		} else if c, ok := r.SetAsTCPSockOpt(); ok {
			withsockopt = true
			remote = c // c is *net.TCPConn
		}
	}
	log.I("com: %s: forward: new conn %s (via: %s) rwext? %t, zerodeadline? %t, sockopt? %t; %s for %s",
		h.proto, cid, via, isrwext, iszerodeadline, withsockopt, tup, uid)

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

	// log.VV("com: %s: queueSummary: %x %x %s", h.proto, h.smmch, h.ctx, s.ID)
	select {
	case <-h.ctx.Done():
		log.D("%s: queueSummary: end: %s", h.proto, s)
	default:
		select {
		case <-h.ctx.Done():
		case h.smmch <- s:
		default:
			log.W("com: %s: sendSummary: dropped: %s", h.proto, s)
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

	log.VV("com: %s: end? sendNotif: %s", h.proto, s)
	h.listener.OnSocketClosed(s) // s.Duration may be uninitialized (zero)
}

// OpenConns implements netstack.GBaseConnHandler
func (h *baseHandler) OpenConns() string {
	return fmt.Sprintf("%d | %s", h.conntracker.Len()/2, h.conntracker.String())
}

// CloseConns implements netstack.GBaseConnHandler
func (h *baseHandler) CloseConns(cidsOrPidsOrUids []string) (closedCids []string) {
	if len(cidsOrPidsOrUids) <= 0 {
		closedCids = h.conntracker.Clear()
	} else {
		closedCids = h.conntracker.UntrackBatch(cidsOrPidsOrUids)
	}

	log.I("com: %s: conns closed %d/%d", h.proto, len(closedCids), len(cidsOrPidsOrUids))
	return closedCids
}

// aux is usually dst domains, ip, ip:port
func (h *baseHandler) flowID(uid string, aux ...string) (fid string) {
	if len(uid) <= 0 { // uid may be empty
		uid = UNKNOWN_UID_STR
	} // or: uid may be unknown
	fid = uid
	for _, v := range aux {
		if len(v) > 0 { // choose the first non-empty aux
			return fid + v
		}
	}
	return
}

func (h *baseHandler) stall(flowid string) (secs uint32) {
	if n := h.fwtracker.Get(flowid); n <= 0 {
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
	h.fwtracker.Set(flowid, newlife)
	if secs > 0 {
		w := time.Duration(secs) * time.Second
		time.Sleep(w)
	}
	return
}

func (h *baseHandler) dnsOverride(conn net.Conn, addr netip.AddrPort, uid string) bool {
	// addr with zone information removed; see: netip.ParseAddrPort which h.resolver relies on
	// addr2 := &net.TCPAddr{IP: addr.IP, Port: addr.Port}
	if addr.IsValid() && h.resolver.IsDnsAddr(addr) {
		// conn closed by the resolver
		core.Gx(h.proto+".dns", func() {
			h.resolver.Serve(h.proto, conn, uid)
		})
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
		log.I("com: %s: handler end %x %x", h.proto, h.ctx, h.smmch)
	})
}

// TODO: Propagate TCP RST using local.Abort(), on appropriate errors.
func upload(cid, proto string, local net.Conn, remote net.Conn, ioch chan<- ioinfo) {
	defer core.Recover(core.Exit11, "c.upload: "+cid)
	defer core.CloseOp(local, core.CopR)
	defer core.CloseOp(remote, core.CopW)
	defer close(ioch)

	n, err := core.Pipe(remote, local)

	log.D("com: %s: %s upload(%d) done(%v) b/w %s",
		proto, cid, n, err, conn2str(local, remote))
	ioch <- ioinfo{n, err}
}

func download(cid, proto string, local net.Conn, remote net.Conn) (n int64, err error) {
	defer core.CloseOp(local, core.CopW)
	defer core.CloseOp(remote, core.CopR)

	n, err = core.Pipe(local, remote)

	log.D("com: %s %s download(%d) done(%v) b/w %s",
		proto, cid, n, err, conn2str(local, remote))
	return
}

func oneRealIPPort(realips []netip.Addr, origipp netip.AddrPort) netip.AddrPort {
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
func makeIPPorts(ips []netip.Addr, origipp netip.AddrPort, cap int) []netip.AddrPort {
	use4 := dialers.Use4()
	use6 := dialers.Use6()

	if cap <= 0 || cap > len(ips) {
		cap = len(ips)
	}

	r := make([]netip.AddrPort, 0, cap)
	// override alg-ip with the first real-ip
	for _, v := range ips { // may contain unspecifed ips
		if len(r) >= cap {
			break
		}
		if v.IsValid() && !v.IsUnspecified() {
			r = append(r, netip.AddrPortFrom(v, origipp.Port()))
		} // else: discard ip
	}

	log.VV("com: makeIPPorts(v4? %t, v6? %t) for %v; tot: %d; in: %v, out: %v",
		use4, use6, origipp, len(ips), ips, r)

	if len(r) > 0 {
		rand.Shuffle(len(r), func(i, j int) {
			r[i], r[j] = r[j], r[i]
		})
		return r
	}
	return []netip.AddrPort{origipp}
}

// algip may or may not be an actual alg ip.
// returned realips may be incoming algip itself or translated from algip,
// depending on whether alg is enabled (ref: undidAlg).
func (h *baseHandler) undoAlg(algip netip.Addr, uid string) (undidAlg bool, realips, domains, probableDomains, blocklists string) {
	r := h.resolver
	didForce := false
	forcePTR := true // force PTR (realip => algans) translation?
	gw := r.Gateway()
	ipok := !algip.IsUnspecified() && algip.IsValid()
	canalg := ipok && gw != nil
	if canalg {
		domains, didForce = gw.PTR(algip, !forcePTR) // does NAT (algip => algans) translation
		if !didForce && len(domains) <= 0 {
			probableDomains, _ = gw.PTR(algip, forcePTR)
		}
		var ips []netip.Addr
		// ips will contain the incoming "algip" arg, in cases where alg is NOT enabled.
		ips, undidAlg = gw.X(algip, uid)
		realips = dnsx.Netip2Csv(ips)
		blocklists = gw.RDNSBL(algip)
	}
	if ipok && len(domains) <= 0 && len(probableDomains) <= 0 {
		if hosts := dialers.Ptr(algip); len(hosts) > 0 {
			probableDomains = strings.Join(hosts, ",")
		}
	}

	logwif(canalg)("com: %s: alg: undoAlg: for [%s] (gw? %t ok? %t, force? %t, withForce? %t) %s => %v (for %s + %s / block: %s)",
		h.proto, uid, gw != nil, undidAlg, didForce, forcePTR, algip, realips, domains, probableDomains, blocklists)
	return
}

// filterFamilyForDialing filters out invalid IPs and IPs that are not
// of the family that the dialer is configured to use.
func filterFamilyForDialing(ipcsv string) (included []netip.Addr, excluded []netip.Addr, excludedIsIncluded bool) {
	if len(ipcsv) <= 0 {
		return
	}
	ips := dnsx.Csv2Netip(ipcsv)
	// assume ipv4 is available on ipv6-only network by the way of
	// any of the 4to6 mechanisms like 464Xlat, DNS64/NAT64, Teredo etc.
	use4 := dialers.Use4()
	use6 := dialers.Use6()
	invalids := 0
	var filtered, unfiltered []netip.Addr
	for _, ip := range ips {
		if !ip.IsValid() {
			invalids++
			continue
		}
		// always include unspecified IPs as it is used by the client
		// to make block/no-block decisions
		if ip.IsUnspecified() || use4 && ip.Is4() || use6 && ip.Is6() {
			filtered = append(filtered, ip)
		} else {
			unfiltered = append(unfiltered, ip)
		}
	}
	logger := log.VV
	// fail open: if no ipv4 then fallback to ipv6, and vice-versa.
	if len(filtered) <= 0 {
		excludedIsIncluded = true
		filtered = unfiltered
		unfiltered = nil
		logger = log.W
	}
	logger("com: filterFamily(v4? %t, v6? %t, fallback? %t): filtered: %d/%d; in: %v, out: %v, ignored: %v + %d",
		use4, use6, excludedIsIncluded, len(filtered), len(ips), ips, filtered, unfiltered, invalids)
	return filtered, unfiltered, excludedIsIncluded
}

// returns conn-id, user-id, flow-id.
// all four values may be empty.
func (h *baseHandler) judge(decision *Mark, aux ...string) (cid, uid, fid string, pids []string) {
	if decision == nil {
		return
	}

	if len(decision.UID) > 0 {
		uid = decision.UID
	} else {
		uid = UNKNOWN_UID_STR
	}
	cid = decision.CID
	fid = h.flowID(uid, aux...)

	if len(decision.PIDCSV) > 0 {
		for v := range strings.SplitSeq(decision.PIDCSV, ",") {
			if v == ipn.Block { // block overrides all other pids
				pids = []string{ipn.Block}
				return
			}
			if len(v) > 0 {
				pids = append(pids, v)
			}
		}
	}

	return
}

func conn2str(a net.Conn, b net.Conn) string {
	ar := a.RemoteAddr()
	br := b.RemoteAddr()
	al := a.LocalAddr()
	bl := b.LocalAddr()
	// may empty out? go.dev/blog/unique
	// (a footnote about interning strings)
	s := core.UniqStr(fmt.Sprintf("a(%v->%v) => b(%v<-%v)", al, ar, bl, br))
	return s
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

func isAnyBlockPid(pids []string) bool {
	return containsPid(pids, ipn.Block)
}

func isAnyBasePid(pids []string) bool {
	return containsPid(pids, ipn.Base)
}

func containsPid(pids []string, pid string) bool {
	return slices.Contains(pids, pid)
}

func extendc(c net.Conn, r time.Duration, w time.Duration) {
	if c != nil {
		if r == w {
			extend(c, r)
		} else {
			extendr(c, r)
			extendw(c, w)
		}
	}
}

func extend(c core.MinConn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		if t.Milliseconds() <= 0 {
			_ = c.SetDeadline(time.Time{})
		} else {
			_ = c.SetDeadline(time.Now().Add(t))
		}
	}
}

func extendr(c core.MinConn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		if t.Milliseconds() <= 0 {
			_ = c.SetDeadline(time.Time{})
		} else {
			_ = c.SetReadDeadline(time.Now().Add(t))
		}
	}
}

func extendw(c core.MinConn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		if t.Milliseconds() <= 0 {
			_ = c.SetDeadline(time.Time{})
		} else {
			_ = c.SetWriteDeadline(time.Now().Add(t))
		}
	}
}

func anyaddrFor(ipp netip.AddrPort) (proto, anyaddr string) {
	return ipn.AnyAddrForUDP(ipp)
}

func logev(err error) log.LogFn {
	f := log.E
	if err == nil {
		f = log.VV
	}
	return f
}

func logwif(cond bool) log.LogFn {
	if cond {
		return log.W
	}
	return log.VV
}

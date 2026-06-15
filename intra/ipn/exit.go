// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"math/rand/v2"
	"net"
	"strconv"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

const (
	fakeExitAddr = "127.0.0.127"
	fakeExitPort = "1337"
)

// exit is a proxy that always dials out to the internet.
type exit struct {
	// TODO: set dnsx.System as DNS for exit and base
	NoDNS
	ProtoAgnostic
	SkipRefresh
	CantPause
	GWNoVia
	id       string
	addr     string
	outbound *protect.RDial // outbound dialer
	status   *core.Volatile[int]
	done     context.CancelFunc
}

// NewExitProxy returns a new exit proxy.
func NewExitProxy(ctx context.Context, c protect.Controller) *exit {
	return newExitProxy(Exit, net.JoinHostPort(fakeExitAddr, fakeExitPort), ctx, c)
}

func NewExitProxyWithID(id, addr string, ctx context.Context, c protect.Controller) *exit {
	if len(id) <= 0 {
		id = hex8()
	}
	if len(addr) <= 0 {
		addr = net.JoinHostPort(fakeExitAddr, no65535())
	}
	return newExitProxy(id, addr, ctx, c)
}

func newExitProxy(id, addr string, ctx context.Context, c protect.Controller) *exit {
	ctx, done := context.WithCancel(ctx)
	h := &exit{
		id:       id,
		addr:     addr,
		outbound: protect.MakeNsRDial(Exit, ctx, c),
		status:   core.NewVolatile(TUP),
		done:     done,
	}
	return h
}

// Handle implements Proxy.
func (h *exit) Handle() uint64 {
	return core.Loc(h)
}

// DialerHandle implements Proxy.
func (h *exit) DialerHandle() uint64 {
	return core.Loc(h.outbound)
}

// Dial implements Proxy.
func (h *exit) Dial(network, addr string) (protect.Conn, error) {
	return h.dial(network, "", addr)
}

// DialBind implements Proxy.
func (h *exit) DialBind(network, local, remote string) (protect.Conn, error) {
	return h.dial(network, local, remote)
}

func (h *exit) dial(network, local, remote string) (protect.Conn, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	// exit always splits
	c, err := localDialStrat(h.outbound, network, local, remote)
	defer localDialStatus(h.status, err)

	kaenabled := maybeKeepAlive(c)
	n, berr := changeBufferSizes(c)
	log.I("proxy: %s: dial(%s) %s => %s, ka? %t, sz? %d (%v); err? %v",
		h.id, network, local, remote, kaenabled, n, berr, err)
	return c, err
}

// Announce implements Proxy.
func (h *exit) Announce(network, local string) (protect.PacketConn, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	c, err := dialers.ListenPacket(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: %s: announce(%s) on %s; err? %v", h.id, network, local, err)
	return c, err
}

// Accept implements Proxy.
func (h *exit) Accept(network, local string) (protect.Listener, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	return dialers.Listen(h.outbound, network, local)
}

// Probe implements Proxy.
func (h *exit) Probe(network, local string) (protect.PacketConn, error) {
	if err := candial(h.status); err != nil {
		return nil, err
	}
	c, err := dialers.Probe(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: %s: probe(%s) on %s; err? %v", h.id, network, local, err)
	return c, err
}

// Dialer implements Proxy.
func (h *exit) Dialer() protect.RDialer {
	return h
}

// ID implements x.Proxy.
func (h *exit) ID() string {
	return h.id
}

// Type implements x.Proxy.
func (h *exit) Type() string {
	return INTERNET
}

// Router implements x.Proxy.
func (h *exit) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *exit) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

// GetAddr implements x.Proxy.
func (h *exit) GetAddr() string {
	return h.addr
}

// Status implements x.Proxy.
func (h *exit) Status() int {
	return h.status.Load()
}

// Stop implements x.Proxy.
func (h *exit) Stop() error {
	h.status.Store(END)
	h.done()
	log.I("proxy: %s: stopped", h.id)
	return nil
}

func localDialStatus(status *core.Volatile[int], err error) bool {
	cur := status.Load()
	if cur == END || cur == TPU {
		return false
	}
	if err != nil {
		return status.Cas(cur, TKO)
	}
	return status.Cas(cur, TOK)
}

func idhandle(p Proxy) string {
	if p == nil || core.IsNil(p) {
		return "<no proxy>"
	}
	return idstr(p) + "@" + hdlstr(p)
}

func refhandle(ref *core.WeakRef[Proxy]) string {
	if ref == nil {
		return "<noproxyref>"
	}
	return idhandle(ref.Load())
}

func idstr(p x.Proxy) string {
	if p == nil || core.IsNil(p) {
		return ""
	}
	return p.ID()
}

func hdlstr(p Proxy) string {
	if p == nil || core.IsNil(p) {
		return ""
	}
	return strconv.FormatUint(p.Handle(), 10)
}

func typstr(p x.Proxy) string {
	if p == nil || core.IsNil(p) {
		return ""
	}
	return p.Type()
}

// create a random hex character string of length 8
func hex8() string {
	b := make([]byte, 4)
	if _, err := crand.Read(b); err != nil {
		return "deadbeef"
	}
	return hex.EncodeToString(b)
}

func no65535() string {
	no := max(rand.IntN(65535), 1024)
	return strconv.Itoa(no)
}

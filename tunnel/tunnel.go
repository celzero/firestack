// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Tunnel represents a session on a TUN device.
type Tunnel interface {
	Mtu() int32
	// IsConnected indicates whether the tunnel is in a connected state.
	IsConnected() bool
	// Disconnect disconnects the tunnel.
	Disconnect()
	// Enabled checks if the tunnel is up and running.
	Enabled() bool
	// Creates a new link using fd (tun device).
	SetLinkAndRoutes(fd, mtu, engine int) error
	// Unsets existing link and closes the fd (tun device).
	Unlink() error
	// Set or unset the pcap sink
	SetPcap(fpcap string) error
	// NIC, IP, TCP, UDP, and ICMP stats.
	Stat() (*x.NetStat, error)
}

type gtunnel struct {
	ctx    context.Context
	done   context.CancelFunc
	stack  *stack.Stack              // a tcpip stack
	ep     netstack.SeamlessEndpoint // endpoint for the stack
	sid    *core.Volatile[int]       // session id (almost always tunnel fd)
	hdl    netstack.GConnHandler     // tcp, udp, and icmp handlers
	pcapio *pcapsink                 // pcap output, if any
	closed atomic.Bool               // open/close?
	once   sync.Once
}

var _ Tunnel = (*gtunnel)(nil)

var (
	errInvalidTunFd = errors.New("invalid tun fd")
	zerowriter      = &nowrite{}
)

func (t *gtunnel) Mtu() int32 {
	if t.IsConnected() {
		// return int32(t.stack.NICInfo()[0].MTU)
		return int32(t.ep.MTU())
	}
	return -1
}

func (t *gtunnel) waitForEndpoint(ctx context.Context) {
	defer core.Recover(core.Exit11, "g.wait")

	const maxchecks = 5
	const betweenChecks = 3 * time.Second
	const uptimeThreshold = 3 * time.Second

	waitStart := time.Now()
	i := 0

	defer func() {
		log.I("tun: waiter: done; #%d, %s", i, core.FmtTimeAsPeriod(waitStart))
	}()

	for i < maxchecks && !t.closed.Load() {
		// wait a bit to let the endpoint settle
		time.Sleep(betweenChecks)
		start := time.Now()
		runid := "g." + strconv.Itoa(i)

		select {
		case <-ctx.Done():
			t.Disconnect() // may already be disconnected
			log.D("tun: waiter: ctx done; #%d", i)
			return
		case <-core.SigFin(runid, t.ep.Wait): // wait until endpoint closes
			log.D("tun: waiter: endpoint not running; #%d", i)
		}

		// if the endpoint was up for more than uptimeThreshold,
		// reset the counter and do another set of maxchecks
		// as a new endpoint may have been created in between
		// see: SetLink -> t.ep.Swap
		if uptime := time.Since(start); uptime >= uptimeThreshold {
			i = 0 // good ep just closed, restart maxchecks
		} else { // no endpoint / bad endpoint still closed
			// ep.Wait was super quick, and it is possible
			// no endpoint will show up in the next few checks
			// but if it does, then i is reset to 0 anyway
			i++
		}
	}
	if !t.closed.Load() {
		// the endpoint closed without a Disconnect, this may happen
		// in cases where a panic was recovered and endpoint was
		// closed without a t.ep.Swap or t.stack.Destroy
		log.U(fmt.Sprintf("Deactivated! Down after %s", core.FmtTimeAsPeriod(waitStart)))
		// todo: disconnect parent tunnel
		t.Disconnect() // may already be disconnected
	}
}

func (t *gtunnel) Disconnect() {
	defer core.Recover(core.Exit11, "g.Disconnect")

	// no core.Recover here as the tunnel is disconnecting anyway
	t.once.Do(func() {
		t.closed.Store(true)
		// go t.Unlink() // may block? takes more time?
		t.stack.Destroy()
		log.I("tun: netstack closed")
	})
}

func (t *gtunnel) Enabled() bool {
	s := t.stack

	// nic may be down even if tunnel is up, when SetLink is in between
	// removing existing nic and creating a new one.
	return s != nil && s.CheckNIC(settings.NICID)
}

func (t *gtunnel) IsConnected() bool {
	return !t.closed.Load()
}

// fd must be non-blocking.
func NewGTunnel(pctx context.Context, fd, mtu int, l3 string, hdl netstack.GConnHandler) (t *gtunnel, rev netstack.GConnHandler, err error) {
	myfd, err := maybeDup(fd) // tunnel will own myfd
	if err != nil {
		return nil, nil, err
	}

	ctx, done := context.WithCancel(pctx)

	sink := newSink(ctx)
	stack := netstack.NewNetstack() // always dual-stack
	// NewEndpoint takes ownership of myfd; closes it on errors
	ep, eerr := netstack.NewEndpoint(myfd, mtu, sink)
	if eerr != nil {
		done()
		return nil, nil, eerr
	}

	var nic tcpip.NICID
	if l3 != settings.IP46 {
		l3 = settings.IP46 // always dual-stack
		log.W("tun: new netstack(%d) l3 is %s needed %s", fd, l3, settings.IP46)
	}
	netstack.Route(stack, l3)
	// Enabled() may temporarily return false when Up() is in progress.
	if nic, err = netstack.Up(stack, ep, hdl); err != nil { // attach new endpoint
		done()
		return nil, nil, err
	}

	rev = netstack.NewReverseGConnHandler(ctx, stack, nic, ep, hdl)

	log.I("tun: new netstack(%d) up; fd(%d=>%d), mtu(%d)", nic, fd, myfd, mtu)

	t = &gtunnel{
		ctx:    ctx,
		done:   done,
		stack:  stack,
		ep:     ep,
		sid:    core.NewVolatile(fd), // fd is the og tun device
		hdl:    hdl,
		pcapio: sink,
		closed: atomic.Bool{},
		once:   sync.Once{},
	}

	go t.waitForEndpoint(ctx)

	return
}

func (t *gtunnel) SetPcap(fp string) error {
	defer core.Recover(core.Exit11, "g.SetPcap")

	pcap := t.pcapio

	ignored := pcap.recycle() // close any existing pcap sink
	if len(fp) == 0 {
		log.I("tun: pcap closed (ignored-err? %v)", ignored)
		return nil // nothing else to do; pcap closed
	} else if len(fp) == 1 {
		// if fdpcap is 0, 1, or 2 then pcap is written to stdout
		ok := pcap.log(true)
		log.I("tun: pcap(%s)/log(%t)", fp, ok)
		return nil // fdbased will write to stdout
	} else if fout, err := os.OpenFile(filepath.Clean(fp), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600); err == nil {
		ignored = pcap.file(fout) // attach
		log.I("tun: pcap(%s)/file(%v) (ignored-err? %v)", fp, fout, ignored)
		return nil // sniffer will write to fout
	} else {
		log.E("tun: pcap(%s); (err? %v)", fp, err)
		return err // no pcap
	}
}

func (t *gtunnel) Unlink() error {
	defer core.Recover(core.Exit11, "g.Unlink")

	return t.ep.Dispose()
}

func (t *gtunnel) SetLinkAndRoutes(fd, mtu, engine int) (err error) {
	defer core.Recover(core.Exit11, "g.SetLinkAndRoutes")

	if err := t.setLink(fd, mtu); err != nil {
		return err
	}
	return t.setRoute(engine)
}

func (t *gtunnel) setLink(fd, mtu int) (err error) {
	defer func() {
		if err != nil {
			t.sid.Store(-1) // reset sid
		} else {
			t.sid.Store(fd) // set sid to fd
		}
	}()

	myfd, err := maybeDup(fd) // endpoint owns myfd
	if err != nil {
		log.E("tun: new link; err %v", err)
		return err
	}

	err = t.ep.Swap(myfd, mtu) // swap fd and mtu

	log.I("tun: new link, fd(%d => %d) mtu(%d); err? %v", fd, myfd, mtu, err)
	return err
}

func (t *gtunnel) setRoute(engine int) error {
	// netstack route is never changed; always dual-stack
	netstack.Route(t.stack, settings.IP46)
	doHappyEyeballs := engine == settings.Ns46
	ok := settings.HappyEyeballs.CompareAndSwap(!doHappyEyeballs, doHappyEyeballs)
	log.I("tun: new route; (no-op) got %s but set %s; enable happy eyeballs? %t / ok? %t",
		settings.L3(engine), settings.IP46, doHappyEyeballs, ok)
	return nil
}

func (t *gtunnel) Stat() (*x.NetStat, error) {
	st, err := netstack.Stat(t.stack)
	if err == nil && st != nil {
		st.TUNSt.Open = !t.closed.Load()
		st.TUNSt.Up = t.ep.IsAttached()
		st.TUNSt.Sid = t.sid.Load() // session id (tunnel fd)
		st.TUNSt.Mtu = int32(t.ep.MTU())
		st.TUNSt.PcapMode = t.pcapio.mode()
		st.TUNSt.EpStats = t.ep.Stat().String()

		if t := t.hdl.TCP(); t != nil {
			st.RDNSIn.OpenConnsTCP = t.OpenConns()
		}
		if u := t.hdl.UDP(); u != nil {
			st.RDNSIn.OpenConnsUDP = u.OpenConns()
		}
		if i := t.hdl.ICMP(); i != nil {
			st.RDNSIn.OpenConnsICMP = i.OpenConns()
		}
	}
	return st, err
}

// copy so golang gc may not close orig fd
func maybeDup(fd int) (int, error) {
	if fd < 0 {
		return 0, errInvalidTunFd
	}
	if settings.OwnTunFd.Load() {
		// if OwnTunFd is true, then do not dup the fd
		// as netstack owns the TUN fd and will not
		// assume ownership of the TUN fd shared with it.
		log.I("tun: assuming fd ownership %d", fd)
		return fd, nil
	}

	// ref: github.com/mdlayher/socket/blob/9c51a391b/conn.go#L309
	// fctnl(2) to dup the fd & set cloexec in one syscall
	newfd, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err == nil { // success
		return newfd, nil
	} else if err == unix.EINVAL { // fallback
		// Mirror the standard library: avoid racing a fork/exec with dup
		// so that child does not inherit socket fds unexpectedly.
		syscall.ForkLock.RLock()
		defer syscall.ForkLock.RUnlock()

		newfd, err := unix.Dup(fd)
		if err == nil {
			unix.CloseOnExec(newfd)
		}
		return newfd, err
	} // other errors?
	return 0, os.NewSyscallError("fcntl", err)
}

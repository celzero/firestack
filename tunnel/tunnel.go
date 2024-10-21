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
	"sync"
	"sync/atomic"
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
	// Write writes input data to the TUN interface.
	Write(data []byte) (int, error)
	// Close connections
	CloseConns(activecsv string) (closedcsv string)
	// Creates a new link using fd (tun device) and mtu.
	SetLink(fd, mtu int) error
	// Unsets existing link and closes the fd (tun device).
	Unlink() error
	// Creates the link and updates the routes
	SetLinkAndRoutes(fd, mtu, engine int) error
	// New route
	SetRoute(engine int) error
	// Set or unset the pcap sink
	SetPcap(fpcap string) error
	// NIC, IP, TCP, UDP, and ICMP stats.
	Stat() (*x.NetStat, error)
}

type gtunnel struct {
	stack  *stack.Stack              // a tcpip stack
	ep     netstack.SeamlessEndpoint // endpoint for the stack
	hdl    netstack.GConnHandler     // tcp, udp, and icmp handlers
	pcapio *pcapsink                 // pcap output, if any
	closed atomic.Bool               // open/close?
	once   sync.Once
}

var _ Tunnel = (*gtunnel)(nil)

var (
	errInvalidTunFd = errors.New("invalid tun fd")
	errNoWriter     = errors.New("no write() on netstack")
	zerowriter      = &nowrite{}
)

func (t *gtunnel) Mtu() int32 {
	// return int32(t.stack.NICInfo()[0].MTU)
	return int32(t.ep.MTU())
}

func (t *gtunnel) waitForEndpoint() {
	defer core.Recover(core.Exit11, "g.wait")

	const betweenChecks = 3 * time.Second
	const uptimeThreshold = 10 * time.Second
	const maxchecks = 3

	waitStart := time.Now()
	i := 0
	for i < maxchecks && !t.closed.Load() {
		// wait a bit to let the endpoint settle
		time.Sleep(betweenChecks)
		start := time.Now()

		t.ep.Wait() // wait until endpoint closes

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
	waitDone := int64(time.Since(waitStart).Milliseconds() / 1000)

	if !t.closed.Load() {
		// the endpoint closed without a Disconnect, this may happen
		// in cases where a panic was recovered and endpoint was
		// closed without a t.ep.Swap or t.stack.Destroy
		log.E("tun: waiter: ep notified close; #%d, %dsecs", i, waitDone)
		log.U(fmt.Sprintf("Deactivated! Down after %dsecs", waitDone))
		// todo: disconnect parent tunnel
		t.Disconnect() // may already be disconnected
	} else {
		log.D("tun: waiter: done; #%d, %dsecs", i, waitDone)
	}
}

func (t *gtunnel) Disconnect() {
	defer core.Recover(core.Exit11, "g.Disconnect")

	// no core.Recover here as the tunnel is disconnecting anyway
	t.once.Do(func() {
		t.closed.Store(true)
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

func (t *gtunnel) Write([]byte) (int, error) {
	// May be: t.endpoint.WritePackets()
	return 0, errNoWriter
}

// fd must be non-blocking.
func NewGTunnel(pctx context.Context, fd, mtu int, hdl netstack.GConnHandler) (t *gtunnel, rev netstack.GConnHandler, err error) {
	dupfd, err := dup(fd) // tunnel will own dupfd
	if err != nil {
		return nil, nil, err
	}

	sink := newSink(pctx)
	stack := netstack.NewNetstack() // always dual-stack
	// NewEndpoint takes ownership of dupfd; closes it on errors
	ep, eerr := netstack.NewEndpoint(dupfd, mtu, sink)
	if eerr != nil {
		return nil, nil, eerr
	}
	netstack.Route(stack, settings.IP46) // always dual-stack

	var nic tcpip.NICID
	// Enabled() may temporarily return false when Up() is in progress.
	if nic, err = netstack.Up(stack, ep, hdl); err != nil { // attach new endpoint
		return nil, nil, err
	}

	rev = netstack.NewReverseGConnHandler(pctx, stack, nic, ep, hdl)

	log.I("tun: new netstack(%d) up; fd(%d), mtu(%d)", nic, fd, mtu)

	t = &gtunnel{
		stack:  stack,
		ep:     ep,
		hdl:    hdl,
		pcapio: sink,
		closed: atomic.Bool{},
		once:   sync.Once{},
	}
	go t.waitForEndpoint()
	context.AfterFunc(pctx, func() {
		log.I("tun: ctx done")
		if !t.closed.Load() {
			t.Disconnect()
		}
	})
	return
}

func (t *gtunnel) CloseConns(activecsv string) (closedcsv string) {
	defer core.Recover(core.Exit11, "g.CloseConns")

	return t.hdl.CloseConns(activecsv)
}

func (t *gtunnel) SetPcap(fp string) error {
	defer core.Recover(core.Exit11, "g.SetPcap")

	pcap := t.pcapio

	ignored := pcap.recycle() // close any existing pcap sink
	if len(fp) == 0 {
		log.I("netstack: pcap closed (ignored-err? %v)", ignored)
		return nil // nothing else to do; pcap closed
	} else if len(fp) == 1 {
		// if fdpcap is 0, 1, or 2 then pcap is written to stdout
		ok := pcap.log(true)
		log.I("netstack: pcap(%s)/log(%t)", fp, ok)
		return nil // fdbased will write to stdout
	} else if fout, err := os.OpenFile(filepath.Clean(fp), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600); err == nil {
		ignored = pcap.file(fout) // attach
		log.I("netstack: pcap(%s)/file(%v) (ignored-err? %v)", fp, fout, ignored)
		return nil // sniffer will write to fout
	} else {
		log.E("netstack: pcap(%s); (err? %v)", fp, err)
		return err // no pcap
	}
}

func (t *gtunnel) SetLinkAndRoutes(fd, mtu, engine int) (err error) {
	// route is always dual-stack (settings.IP46); never changed
	log.I("tun: requested route (%s); unchanged", settings.L3(engine))
	return t.SetLink(fd, mtu)
}

func (t *gtunnel) Unlink() error {
	defer core.Recover(core.Exit11, "g.Unlink")

	return t.ep.Dispose()
}

func (t *gtunnel) SetLink(fd, mtu int) error {
	defer core.Recover(core.Exit11, "g.SetLink")

	dupfd, err := dup(fd) // tunnel will own dupfd
	if err != nil {
		log.E("tun: new link; err %v", err)
		return err
	}

	err = t.ep.Swap(dupfd, mtu) // swap fd and mtu

	log.I("tun: new link; fd(%d), mtu(%d); err? %v", dupfd, mtu, err)
	return err
}

func (t *gtunnel) SetRoute(engine int) error {
	defer core.Recover(core.Exit11, "g.SetRoute")

	// netstack route is never changed; always dual-stack
	netstack.Route(t.stack, settings.IP46)
	log.I("tun: new route; (no-op) got %s but set %s", settings.L3(engine), settings.IP46)
	return nil
}

func (t *gtunnel) Stat() (*x.NetStat, error) {
	st, err := netstack.Stat(t.stack)
	if err == nil && st != nil {
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

func dup(fd int) (int, error) {
	if fd < 0 {
		return -1, errInvalidTunFd
	}

	// copy so golang gc may not close orig fd
	newfd, err := unix.Dup(fd)
	if err != nil {
		return -1, err
	}

	// kt-land gives up its ownership of fd
	return newfd, nil
}

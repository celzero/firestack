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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Tunnel represents a session on a TUN device.
type Tunnel interface {
	Mtu() int
	// IsConnected indicates whether the tunnel is in a connected state.
	IsConnected() bool
	// Disconnect disconnects the tunnel.
	Disconnect()
	// Enabled checks if the tunnel is up.
	Enabled() bool
	// Write writes input data to the TUN interface.
	Write(data []byte) (int, error)
	// Close connections
	CloseConns(activecsv string) (closedcsv string)
	// Creates a new link using fd (tun device) and mtu.
	SetLink(fd, mtu int) error
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

	// mutable fields
	mtu *core.Volatile[int] // mtu of the tun device
}

type pcapsink struct {
	sink  *core.Volatile[io.WriteCloser]
	inC   chan []byte   // always buffered
	doneC chan struct{} // always unbuffered
}

// nowrite rejects all writes.
type nowrite struct{}

func (*nowrite) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (*nowrite) Close() error              { return nil }

var _ io.WriteCloser = (*nowrite)(nil)
var _ Tunnel = (*gtunnel)(nil)

var (
	errInvalidTunFd = errors.New("invalid tun fd")
	errNoWriter     = errors.New("no write() on netstack")
	zerowriter      = &nowrite{}
)

func (p *pcapsink) Write(b []byte) (int, error) {
	select {
	case <-p.doneC: // closed
		return 0, io.ErrClosedPipe
	case p.inC <- b:
		return len(b), nil
	default: // drop
		return 0, io.ErrNoProgress
	}
}

// writeAsync consumes [p.in] until close.
func (p *pcapsink) writeAsync() {
	for b := range p.inC { // winsy spider
		w := p.sink.Load() // always re-load current writer
		if w != nil && w != zerowriter {
			n, err := w.Write(b)
			log.VV("tun: pcap: writeAsync: n: %d, err? %v", n, err)
		} // else: no op
	}
}

func (p *pcapsink) Recycle() error {
	p.log(false)       // detach
	err := p.file(nil) // detach
	return err
}

func (p *pcapsink) Close() error {
	defer core.Go("pcap.Close", func() {
		time.Sleep(2 * time.Second)
		close(p.inC) // signal writeAsync to exit
	})
	defer close(p.doneC)

	return p.Recycle()
}

// begin writes pcap header to w.
// from: github.com/google/gvisor/blob/596e8d22/pkg/tcpip/link/sniffer/sniffer.go#L93
func (p *pcapsink) begin(w io.Writer) error {
	_, offset := time.Date(0, 0, 0, 0, 0, 0, 0, time.Local).Zone()
	return binary.Write(w, binary.LittleEndian, core.PcapHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		Thiszone:     int32(offset),
		Sigfigs:      0,
		Snaplen:      netstack.SnapLen, // must match netstack.asSniffer()
		Network:      101,              // LINKTYPE_RAW
	})
}

func (p *pcapsink) file(f io.WriteCloser) (err error) {
	if f == nil || core.IsNil(f) {
		f = zerowriter
	}

	old := p.sink.Tango(f) // old may be nil
	core.CloseOp(old, core.CopRW)

	y := f != zerowriter
	if y {
		err = p.begin(f) // write pcap header before any packets
		log.I("tun: pcap: begin: writeHeader; err(%v)", err)
	}
	netstack.FilePcap(y) // signal netstack to write packets
	return
}

func (p *pcapsink) log(y bool) bool {
	return netstack.LogPcap(y)
}

func (t *gtunnel) Mtu() int {
	// return int(t.stack.NICInfo()[0].MTU)
	return t.mtu.Load()
}

func (t *gtunnel) wait() {
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
		t.Disconnect() // may already be disconnected
	} else {
		log.D("tun: waiter: done; #%d, %dsecs", i, waitDone)
	}
}

func (t *gtunnel) Disconnect() {
	// no core.Recover here as the tunnel is disconnecting anyway
	t.once.Do(func() {
		t.closed.Store(true)

		s := t.stack
		p := t.pcapio
		hdl := t.hdl

		herr := hdl.Close()
		perr := p.Close()
		s.Destroy()
		log.I("tun: netstack closed; errs: %v / %v", herr, perr)
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

func newSink() *pcapsink {
	// go.dev/play/p/4qANL9VSDXb
	p := new(pcapsink)
	p.sink = core.NewVolatile[io.WriteCloser](zerowriter)
	p.log(false) // no log, which is enabled by default
	p.inC = make(chan []byte, 128)
	p.doneC = make(chan struct{})
	core.Go("pcap.w", func() { p.writeAsync() })
	return p
}

func NewGTunnel(fd, mtu int, tcph netstack.GTCPConnHandler, udph netstack.GUDPConnHandler, icmph netstack.GICMPHandler) (t *gtunnel, err error) {
	dupfd, err := dup(fd) // tunnel will own dupfd
	if err != nil {
		return nil, err
	}

	sink := newSink()
	hdl := netstack.NewGConnHandler(tcph, udph, icmph)
	stack := netstack.NewNetstack() // always dual-stack
	// NewEndpoint takes ownership of dupfd; closes it on errors
	ep, err := netstack.NewEndpoint(dupfd, mtu, sink)
	if err != nil {
		return nil, err
	}
	netstack.Route(stack, settings.IP46) // always dual-stack

	t = &gtunnel{
		stack:  stack,
		ep:     ep,
		hdl:    hdl,
		pcapio: sink,
		closed: atomic.Bool{},
		once:   sync.Once{},
		mtu:    core.NewVolatile(0),
	}

	// Enabled() may temporarily return false when Up() is in progress.
	if err = netstack.Up(stack, ep, hdl); err != nil { // attach new endpoint
		return nil, err
	}

	log.I("tun: new netstack up; fd(%d), mtu(%d)", fd, mtu)

	go t.wait() // wait for endpoint to close

	return
}

func (t *gtunnel) CloseConns(activecsv string) (closedcsv string) {
	return t.hdl.CloseConns(activecsv)
}

func (t *gtunnel) SetPcap(fp string) error {
	pcap := t.pcapio

	ignored := pcap.Recycle() // close any existing pcap sink
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

func (t *gtunnel) SetLink(fd, mtu int) error {
	dupfd, err := dup(fd) // tunnel will own dupfd
	if err != nil {
		log.E("tun: new link; err %v", err)
		return err
	}

	err = t.ep.Swap(dupfd, mtu) // swap fd and mtu
	t.mtu.Store(mtu)

	log.I("tun: new link; fd(%d), mtu(%d); err? %v", dupfd, mtu, err)
	return err
}

func (t *gtunnel) SetRoute(engine int) error {
	// netstack route is never changed; always dual-stack
	netstack.Route(t.stack, settings.IP46)
	log.I("tun: new route; (no-op) got %s but set %s", settings.L3(engine), settings.IP46)
	return nil
}

func (t *gtunnel) Stat() (*x.NetStat, error) {
	return netstack.Stat(t.stack)
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

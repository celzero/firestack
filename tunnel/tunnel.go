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
	"errors"
	"io"
	"os"
	"sync"

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
	// Write writes input data to the TUN interface.
	Write(data []byte) (int, error)
	// Creates a new link using fd (tun device) and mtu.
	SetLink(fd, mtu int) error
	// internal method that creates the link and updates the routes
	setLinkAndRoutes(fd, mtu, engine int) error
	// New route
	SetRoute(engine int) error
	// Set or unset the pcap sink
	SetPcap(fpcap string) error
}

// netstack

var errStackMissing = errors.New("tun: netstack not initialized")
var errInvalidTunFd = errors.New("invalid tun fd")
var errNoWriter = errors.New("no write() on netstack")

type gtunnel struct {
	mu     *sync.RWMutex         // protects all fields
	stack  *stack.Stack          // a tcpip stack
	hdl    netstack.GConnHandler // tcp, udp, and icmp handlers
	mtu    int                   // mtu of the tun device
	pcapio *pcapsink             // pcap output, if any
}

type pcapsink struct {
	sync.RWMutex // protects sink
	sink         io.WriteCloser
}

func (p *pcapsink) Write(b []byte) (int, error) {
	go p.writeAsync(b)
	return len(b), nil
}

func (p *pcapsink) writeAsync(b []byte) {
	p.RLock()
	w := p.sink
	p.RUnlock()

	if w != nil {
		w.Write(b)
	} // else: no op
}

func (p *pcapsink) Close() error {
	p.log(false)       // detach
	err := p.file(nil) // detach
	return err
}

func (p *pcapsink) file(f io.WriteCloser) (err error) {
	p.Lock()
	w := p.sink
	p.sink = f
	p.Unlock()

	if w != nil {
		err = w.Close()
	}
	y := f != nil
	netstack.FilePcap(y)
	return
}

func (p *pcapsink) log(y bool) bool {
	return netstack.LogPcap(y)
}

func (t *gtunnel) Mtu() int {
	return t.mtu
}

func (t *gtunnel) closeHandlers() {
	t.mu.Lock()
	hdl := t.hdl
	t.hdl = nil
	t.mu.Unlock()

	if hdl == nil {
		log.I("tun: handlers already closed")
		return
	}
	err := hdl.Close()
	log.I("tun: handlers closed; err? %v", err)
}

func (t *gtunnel) closePcap() {
	t.mu.Lock()
	p := t.pcapio
	t.pcapio = nil
	t.mu.Unlock()

	if p == nil {
		log.I("tun: pcap already closed")
		return
	}
	err := p.Close()
	log.I("tun: pcap closed; err? %v", err)
}

func (t *gtunnel) closeStack() {
	t.mu.Lock()
	s := t.stack
	t.stack = nil
	t.mu.Unlock()

	if s == nil {
		log.I("tun: stack already closed")
		return
	}
	s.Destroy()
	log.I("tun: netstack closed")
}

func (t *gtunnel) Disconnect() {
	t.closeHandlers()
	t.closePcap()
	t.closeStack()
}

func (t *gtunnel) IsConnected() bool {
	t.mu.RLock()
	s := t.stack
	t.mu.RUnlock()

	return s != nil && s.CheckNIC(settings.NICID)
}

func (t *gtunnel) Write([]byte) (int, error) {
	// May be: t.endpoint.WritePackets()
	return 0, errNoWriter
}

func NewGTunnel(fd, mtu, engine int, tcph netstack.GTCPConnHandler, udph netstack.GUDPConnHandler, icmph netstack.GICMPHandler) (t Tunnel, err error) {
	hdl := netstack.NewGConnHandler(tcph, udph, icmph)
	stack := netstack.NewNetstack() // always dual-stack
	sink := &pcapsink{}
	mu := &sync.RWMutex{}
	t = &gtunnel{mu, stack, hdl, mtu, sink}

	err = t.setLinkAndRoutes(fd, mtu, engine) // creates endpoint / brings up nic
	if err != nil {
		return nil, err
	}

	log.I("tun: new netstack up; fd(%d), l3(%v), mtu(%d)", fd, engine, mtu)
	return
}

func (t *gtunnel) SetPcap(fpcap string) error {
	t.mu.RLock()
	pcap := t.pcapio
	t.mu.RUnlock()

	if pcap == nil {
		return errStackMissing
	}
	ignored := pcap.Close() // close any existing pcap sink

	if len(fpcap) == 0 {
		log.I("netstack: pcap closed (ignored-err? %v)", ignored)
		return nil // nothing else to do; pcap is closed
	} else if len(fpcap) == 1 {
		// if fdpcap is 0, 1, or 2 then pcap is written to stdout
		ok := pcap.log(true)
		log.I("netstack: pcap(%s)/log(%t)", fpcap, ok)
		return nil // fdbased will write to stdout
	} else if fout, err := os.OpenFile(fpcap, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600); err == nil {
		ignored = pcap.file(fout) // attach
		log.I("netstack: pcap(%s)/file(%v) (ignored-err? %v)", fpcap, fout, ignored)
		return nil // sniffer will write to fout
	} else {
		log.E("netstack: pcap(%s); (err? %v)", fpcap, err)
		return err // no pcap
	}
}

func (t *gtunnel) setLinkAndRoutes(fd, mtu, engine int) (err error) {
	if err = t.SetLink(fd, mtu); err == nil {
		err = t.SetRoute(engine)
	}
	return
}

func (t *gtunnel) SetLink(fd, mtu int) error {
	t.mu.RLock()
	s := t.stack
	hdl := t.hdl
	pcap := t.pcapio
	t.mu.RUnlock()

	if s == nil || hdl == nil || pcap == nil {
		log.W("tun: link not set; stack? %t, hdl? %v, pcap? %v", s != nil, hdl != nil, pcap != nil)
		return errStackMissing
	}

	dupfd, err := dup(fd) // tunnel will own dupfd
	if err != nil {
		return err
	}
	// NewEndpoint takes ownership of dupfd; closes it on errors
	ep, err := netstack.NewEndpoint(dupfd, mtu, pcap)
	if err != nil {
		return err
	}

	if err = netstack.Up(s, ep, hdl); err != nil { // attach new endpoint
		return err
	}

	log.I("tun: new link; fd(%d), mtu(%d)", dupfd, mtu)
	t.mtu = mtu
	return nil
}

func (t *gtunnel) SetRoute(engine int) error {
	t.mu.RLock()
	s := t.stack
	t.mu.RUnlock()

	if s == nil {
		return errStackMissing
	}
	l3 := settings.L3(engine)
	netstack.Route(s, l3)
	log.I("tun: new route; l3(%v)", l3)
	return nil
}

func dup(fd int) (int, error) {
	if fd < 0 {
		return -1, errInvalidTunFd
	}

	// copy fd so that golang apis don't close fd
	newfd, err := unix.Dup(fd)
	if err != nil {
		return -1, err
	}

	// kt-land gives up its ownership of fd
	return newfd, nil
}

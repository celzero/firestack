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
	"syscall"

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
	// Update fd and mtu
	SetLink(fd, mtu int) error
	// New route
	NewRoute(l3 string) error
	// Set or unset the pcap sink
	SetPcap(fpcap string) error
}

// netstack

const invalidfd = -1

var errStackMissing = errors.New("tun: netstack not initialized")
var errInvalidTunFd = errors.New("invalid tun fd")

type gtunnel struct {
	endpoint stack.LinkEndpoint    // wires up tun fd to netstack
	stack    *stack.Stack          // a tcpip stack
	hdl      netstack.GConnHandler // tcp, udp, and icmp handlers
	mtu      int                   // mtu of the tun device
	fdref    int                   // the tun device
	pcapio   *pcapsink             // pcap output, if any
}

type pcapsink struct {
	sync.RWMutex
	sink io.WriteCloser
}

func (p *pcapsink) Write(b []byte) (int, error) {
	go p.writeAsync(b)
	return len(b), nil
}

func (p *pcapsink) writeAsync(b []byte) {
	p.RLock()
	defer p.RUnlock()
	if p.sink != nil {
		p.sink.Write(b)
	} // else: no op
}

func (p *pcapsink) Close() error {
	p.log(false)       // detach
	err := p.file(nil) // detach
	return err
}

func (p *pcapsink) file(w io.WriteCloser) (err error) {
	p.Lock()
	defer p.Unlock()

	if p.sink != nil {
		err = p.sink.Close()
	}
	y := w != nil
	p.sink = w
	netstack.FilePcap(y)
	return
}

func (p *pcapsink) log(y bool) bool {
	return netstack.LogPcap(y)
}

func (t *gtunnel) Mtu() int {
	return t.mtu
}

func (t *gtunnel) closePcap() {
	if t.pcapio == nil {
		log.I("tun: pcap already closed")
		return
	}

	if err := t.pcapio.Close(); err != nil {
		log.E("tun: close(pcap) fail, err(%v)", err)
	} else {
		log.I("tun: pcap closed")
	}
}

func (t *gtunnel) closeStack() {
	if t.stack == nil {
		log.I("tun: stack already closed")
		return
	}
	t.stack.Close()
	t.stack = nil
	log.I("tun: netstack closed")
}

func (t *gtunnel) closeEndpoint() {
	if t.endpoint == nil {
		log.I("tun: endpoint already closed")
		return
	}

	// close endpoint
	t.endpoint.Attach(nil)
	// close tun fd
	if err := syscall.Close(t.fdref); err != nil {
		log.E("tun: close(fd) fail, err(%v)", err)
	} else {
		log.I("tun: fd closed %d", t.fdref)
	}
	t.endpoint = nil
	t.fdref = invalidfd
	log.I("tun: endpoint closed")
}

func (t *gtunnel) Disconnect() {
	t.closeEndpoint()
	t.closePcap()
	t.closeStack()
}

func (t *gtunnel) IsConnected() bool {
	// TODO: check t.endpoint.IsAttached()?
	return t.fdref != invalidfd
}

func (t *gtunnel) Write([]byte) (int, error) {
	// May be: t.endpoint.WritePackets()
	return 0, errors.New("no write() on netstack")
}

func NewGTunnel(fd, mtu int, l3 string, tcph netstack.GTCPConnHandler, udph netstack.GUDPConnHandler, icmph netstack.GICMPHandler) (t Tunnel, err error) {
	var endpoint stack.LinkEndpoint

	hdl := netstack.NewGConnHandler(tcph, udph, icmph)

	stack := netstack.NewNetstack(settings.IP46) // force dual stack
	netstack.Route(stack, l3)                    // set routes as per preference

	sink := &pcapsink{}

	dupfd, err := dup(fd) // tunnel will own dupfd
	if err != nil {
		return nil, err
	}
	endpoint, err = netstack.NewEndpoint(dupfd, mtu, sink)
	if err != nil {
		return
	}

	if err = netstack.Up(stack, endpoint, hdl); err != nil {
		return
	}

	t = &gtunnel{endpoint, stack, hdl, mtu, dupfd, sink}

	log.I("tun: new netstack up; fd(%d), l3(%v), mtu(%d)", dupfd, l3, mtu)
	return
}

func (t *gtunnel) SetPcap(fpcap string) error {
	ignored := t.pcapio.Close() // close any existing pcap sink

	if len(fpcap) == 0 {
		log.I("netstack: pcap closed (ignored-err? %v)", ignored)
		return nil // nothing else to do; pcap is closed
	} else if len(fpcap) == 1 {
		// if fdpcap is 0, 1, or 2 then pcap is written to stdout
		ok := t.pcapio.log(true)
		log.I("netstack: pcap(%s)/log(%t)", fpcap, ok)
		return nil // fdbased will write to stdout
	} else if fout, err := os.OpenFile(fpcap, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600); err == nil {
		ignored = t.pcapio.file(fout) // attach
		log.I("netstack: pcap(%s)/file(%v) (ignored-err? %v)", fpcap, fout, ignored)
		return nil // sniffer will write to fout
	} else {
		log.E("netstack: pcap(%s); (err? %v)", fpcap, err)
		return err // no pcap
	}
}

func (t *gtunnel) SetLink(fd, mtu int) error {
	if t.stack == nil {
		return errStackMissing
	}

	t.closeEndpoint() // detach previous endpoint

	dupfd, err := dup(fd) // tunnel will own dupfd
	if err != nil {
		return err
	}
	ep, err := netstack.NewEndpoint(dupfd, mtu, t.pcapio)
	if err != nil {
		return err
	}

	if err = netstack.Up(t.stack, ep, t.hdl); err != nil { // attach new endpoint
		return err
	}

	log.I("tun: new link; fd(%d), mtu(%d)", dupfd, mtu)
	t.endpoint = ep
	t.mtu = mtu
	t.fdref = dupfd
	return nil
}

func (t *gtunnel) NewRoute(l3 string) error {
	if t.stack == nil {
		return errStackMissing
	}

	netstack.Route(t.stack, l3)
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

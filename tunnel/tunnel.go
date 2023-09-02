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
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/settings"
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
	SetLink(fd, mtu int, pcap string) error
	// New route
	NewRoute(l3 string) error
}

// netstack

const invalidfd = -1

var errStackMissing = errors.New("tun: netstack not initialized")

type gtunnel struct {
	endpoint stack.LinkEndpoint
	stack    *stack.Stack
	l3       string
	hdl      netstack.GConnHandler
	fdref    int
	pcapio   io.Closer
	mtu      int
}

func (t *gtunnel) Mtu() int {
	return t.mtu
}

func (t *gtunnel) closeStack() {
	if t.stack == nil {
		log.I("tun: stack already closed")
		return
	}
	t.stack.Close()
	t.stack = nil
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
	// close pcap if any
	if t.pcapio != nil {
		if err := t.pcapio.Close(); err != nil {
			log.E("tun: close(pcap) fail, err(%v)", err)
		} else {
			log.I("tun: pcap closed")
		}
	}
	t.endpoint = nil
	t.pcapio = nil
	t.fdref = invalidfd
}

func (t *gtunnel) Disconnect() {
	t.closeEndpoint()
	t.closeStack()
	log.I("tun: netstack closed")
}

func (t *gtunnel) IsConnected() bool {
	// TODO: check t.endpoint.IsAttached()?
	return t.fdref != invalidfd
}

func (t *gtunnel) Write([]byte) (int, error) {
	// May be: t.endpoint.WritePackets()
	return 0, errors.New("no write() on netstack")
}

func NewGTunnel(fd, mtu int, fpcap, l3 string, tcph netstack.GTCPConnHandler, udph netstack.GUDPConnHandler, icmph netstack.GICMPHandler) (t Tunnel, err error) {
	var endpoint stack.LinkEndpoint
	hdl := netstack.NewGConnHandler(tcph, udph, icmph)
	stack := netstack.NewNetstack(settings.IP46) // force dual stack
	netstack.Route(stack, l3)

	endpoint, err = netstack.NewEndpoint(fd, mtu)
	if err != nil {
		return
	}

	var pcapio io.Closer // may be nil
	if len(fpcap) > 0 {
		// if fdpcap is 0, 1, or 2 then pcap is written to stdout
		if endpoint, pcapio, err = netstack.PcapOf(endpoint, fpcap); err != nil {
			log.E("tun: pcap(%s) err(%v)", fpcap, err)
			return
		}
	}

	if err := netstack.Up(stack, endpoint, hdl); err != nil {
		return nil, err
	}

	log.I("tun: new netstack up; fd(%d), pcap(%t), l3(%v), mtu(%d)", fd, len(fpcap) > 0, l3, mtu)
	return &gtunnel{endpoint, stack, l3, hdl, fd, pcapio, mtu}, nil
}

func (t *gtunnel) SetLink(fd, mtu int, fpcap string) error {
	if t.stack == nil {
		return errStackMissing
	}

	t.closeEndpoint() // detach previous endpoint

	ep, err := netstack.NewEndpoint(fd, mtu)
	if err != nil {
		return err
	}

	var pcapio io.Closer // may be nil
	if len(fpcap) > 0 {
		// if fdpcap is 0, 1, or 2 then pcap is written to stdout
		if ep, pcapio, err = netstack.PcapOf(ep, fpcap); err != nil {
			log.E("tun: pcap(%s) err(%v)", fpcap, err)
			return err
		}
	}

	if err = netstack.Up(t.stack, ep, t.hdl); err != nil { // attach new endpoint
		return err
	}

	log.I("tun: new link; fd(%d), pcap(%t), l3(%v), mtu(%d)", fd, len(fpcap) > 0, t.l3, mtu)
	t.endpoint = ep
	t.mtu = mtu
	t.pcapio = pcapio
	t.fdref = fd
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

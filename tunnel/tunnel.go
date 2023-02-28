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
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
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
}

// netstack

const invalidfd = -1

type gtunnel struct {
	endpoint stack.LinkEndpoint
	stack    *stack.Stack
	fdref    int
	mtu      int
}

func (t *gtunnel) Mtu() int {
	return t.mtu
}

func (t *gtunnel) Disconnect() {
	if !t.IsConnected() {
		log.Infof("tun: cannot disconnect an unconnected fd")
		return
	}
	go func() {
		t.endpoint.Attach(nil)
		t.stack.Close()
		log.Infof("tun: stack closed")
	}()
	if err := syscall.Close(t.fdref); err != nil {
		log.Errorf("tun: close(fd) fail, err(%v)", err)
	}
	log.Infof("tun: disconnected %d", t.fdref)
	t.fdref = invalidfd
}

func (t *gtunnel) IsConnected() bool {
	// TODO: check t.endpoint.IsAttached()?
	return t.fdref != invalidfd
}

func (t *gtunnel) Write([]byte) (int, error) {
	// May be: t.endpoint.WritePackets()
	return 0, errors.New("no write() on netstack")
}

func NewGTunnel(fd int, fdpcap int, l3 string, mtu int, tcph netstack.GTCPConnHandler, udph netstack.GUDPConnHandler, icmph netstack.GICMPHandler) (t Tunnel, err error) {
	var endpoint stack.LinkEndpoint
	hdl := netstack.NewGConnHandler(tcph, udph, icmph)
	stack := netstack.NewNetstack(l3)

	endpoint, err = netstack.NewEndpoint(fd, mtu)
	if err != nil {
		return
	}
	if fdpcap > invalidfd {
		// if fdpcap is 0, 1, or 2 then pcap is written to stdout
		if endpoint, err = netstack.PcapOf(endpoint, fdpcap); err != nil {
			log.Errorf("tun: pcap(%d) err(%v)", fdpcap, err)
			return
		}
	}

	if err := netstack.Up(stack, endpoint, hdl); err != nil {
		return nil, err
	}

	return &gtunnel{endpoint, stack, fd, mtu}, nil
}

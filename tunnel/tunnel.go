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

	"github.com/celzero/firestack/intra/netstack"
	"github.com/eycorsican/go-tun2socks/core"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Tunnel represents a session on a TUN device.
type Tunnel interface {
	// IsConnected indicates whether the tunnel is in a connected state.
	IsConnected() bool
	// Disconnect disconnects the tunnel.
	Disconnect()
	// Write writes input data to the TUN interface.
	Write(data []byte) (int, error)
}

type tunnel struct {
	tunWriter   io.WriteCloser
	lwipStack   core.LWIPStack
	isConnected bool
}

func (t *tunnel) IsConnected() bool {
	return t.isConnected
}

func (t *tunnel) Disconnect() {
	if !t.isConnected {
		return
	}
	t.isConnected = false
	t.lwipStack.Close()
	t.tunWriter.Close()
}

func (t *tunnel) Write(data []byte) (int, error) {
	if !t.isConnected {
		return 0, errors.New("failed to write, network stack closed")
	}
	return t.lwipStack.Write(data)
}

func NewTunnel(tunWriter io.WriteCloser, lwipStack core.LWIPStack) Tunnel {
	return &tunnel{tunWriter, lwipStack, true}
}

// netstack

type gtunnel struct {
	endpoint    stack.LinkEndpoint
	stack       *stack.Stack
	isConnected bool
}

func (t *gtunnel) Disconnect() {
	// FIXME: figure out what must be done here?
	t.isConnected = false
}

func (t *gtunnel) IsConnected() bool {
	return t.isConnected
}

func (t *gtunnel) Write([]byte) (int, error) {
	return 0, errors.New("no write() on gvisor netstack")
}

func NewGTunnel(fd int, mtu uint32, tcph netstack.GTCPConnHandler, udph netstack.GUDPConnHandler) (Tunnel, error) {
	endpoint, err := netstack.NewEndpoint(fd, mtu)
	if err != nil {
		return nil, err
	}
	ghdl := netstack.NewGConnHandler(tcph, udph)
	stack, err := netstack.NewStack(ghdl, endpoint)
	if err != nil {
		return nil, err
	}

	return &gtunnel{endpoint, stack, true}, nil
}

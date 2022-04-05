// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2018 The gVisor Authors.
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

// Adopted from: github.com/google/gvisor/blob/f33d034/pkg/tcpip/link/fdbased/packet_dispatchers.go
package netstack

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type iovecBuffer struct {
	// views are the actual buffers that hold the packet contents.
	views []buffer.View

	// iovecs are initialized with base pointers/len of the corresponding
	// entries in the views defined above, except when GSO is enabled
	// (skipsVnetHdr) then the first iovec points to a buffer for the vnet header
	// which is stripped before the views are passed up the stack for further
	// processing.
	iovecs []unix.Iovec

	// sizes is an array of buffer sizes for the underlying views. sizes is
	// immutable.
	sizes []int

	// skipsVnetHdr is true if virtioNetHdr is to skipped.
	//skipsVnetHdr bool
}

func newIovecBuffer(sizes []int) *iovecBuffer {
	b := &iovecBuffer{
		views: make([]buffer.View, len(sizes)),
		sizes: sizes,
		//	skipsVnetHdr: skipsVnetHdr,
	}
	/*niov := len(b.views)
	if b.skipsVnetHdr {
		niov++
	}
	b.iovecs = make([]unix.Iovec, niov)*/
	b.iovecs = make([]unix.Iovec, len(b.views))
	return b
}

func (b *iovecBuffer) nextIovecs() []unix.Iovec {
	vnetHdrOff := 0
	/*	if b.skipsVnetHdr {
			var vnetHdr [virtioNetHdrSize]byte
			// The kernel adds virtioNetHdr before each packet, but
			// we don't use it, so so we allocate a buffer for it,
			// add it in iovecs but don't add it in a view.
			b.iovecs[0] = unix.Iovec{Base: &vnetHdr[0]}
			b.iovecs[0].SetLen(virtioNetHdrSize)
			vnetHdrOff++
		}
	*/for i := range b.views {
		if b.views[i] != nil {
			break
		}
		v := buffer.NewView(b.sizes[i])
		b.views[i] = v
		b.iovecs[i+vnetHdrOff] = unix.Iovec{Base: &v[0]}
		b.iovecs[i+vnetHdrOff].SetLen(len(v))
	}
	return b.iovecs
}

func (b *iovecBuffer) pullViews(n int) buffer.VectorisedView {
	var views []buffer.View
	c := 0
	/*	if b.skipsVnetHdr {
		c += virtioNetHdrSize
		if c >= n {
			// Nothing in the packet.
			return buffer.NewVectorisedView(0, nil)
		}
	}*/
	for i, v := range b.views {
		c += len(v)
		if c >= n {
			b.views[i].CapLength(len(v) - (c - n))
			views = append([]buffer.View(nil), b.views[:i+1]...)
			break
		}
	}
	// Remove the first len(views) used views from the state.
	for i := range views {
		b.views[i] = nil
	}
	/*	if b.skipsVnetHdr {
		// Exclude the size of the vnet header.
		n -= virtioNetHdrSize
	}*/
	return buffer.NewVectorisedView(n, views)
}

// stopFd is an eventfd used to signal the stop of a dispatcher.
type stopFd struct {
	efd int
}

func newStopFd() (stopFd, error) {
	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		return stopFd{efd: -1}, fmt.Errorf("failed to create eventfd: %w", err)
	}
	return stopFd{efd: efd}, nil
}

// stop writes to the eventfd and notifies the dispatcher to stop. It does not
// block.
func (s *stopFd) stop() {
	increment := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	if n, err := unix.Write(s.efd, increment); n != len(increment) || err != nil {
		// There are two possible errors documented in eventfd(2) for writing:
		// 1. We are writing 8 bytes and not 0xffffffffffffff, thus no EINVAL.
		// 2. stop is only supposed to be called once, it can't reach the limit,
		// thus no EAGAIN.
		panic(fmt.Sprintf("write(efd) = (%d, %s), want (%d, nil)", n, err, len(increment)))
	}
}

// readVDispatcher uses readv() system call to read inbound packets and
// dispatches them.
type readVDispatcher struct {
	stopFd
	// fd is the file descriptor used to send and receive packets.
	fd int

	// e is the endpoint this dispatcher is attached to.
	e *endpoint

	// buf is the iovec buffer that contains the packet contents.
	buf *iovecBuffer
}

func newReadVDispatcher(fd int, e *endpoint) (linkDispatcher, error) {
	stopFd, err := newStopFd()
	if err != nil {
		return nil, err
	}
	d := &readVDispatcher{
		stopFd: stopFd,
		fd:     fd,
		e:      e,
	}

	//	skipsVnetHdr := d.e.gsoKind == stack.HWGSOSupported
	d.buf = newIovecBuffer(BufConfig)
	return d, nil
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (d *readVDispatcher) dispatch() (bool, tcpip.Error) {
	n, err := rawfile.BlockingReadvUntilStopped(d.efd, d.fd, d.buf.nextIovecs())
	if n <= 0 || err != nil {
		return false, err
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: d.buf.pullViews(n),
	})
	defer pkt.DecRef()

	var p tcpip.NetworkProtocolNumber
	// hdrSize always zero; unused
	if d.e.hdrSize > 0 {
		hdr, ok := pkt.LinkHeader().Consume(d.e.hdrSize)
		if !ok {
			return false, nil
		}
		p = header.Ethernet(hdr).Type()
	} else {
		// We don't get any indication of what the packet is, so try to guess
		// if it's an IPv4 or IPv6 packet.
		// IP version information is at the first octet, so pulling up 1 byte.
		h, ok := pkt.Data().PullUp(1)
		if !ok {
			return true, nil
		}
		switch header.IPVersion(h) {
		case header.IPv4Version:
			p = header.IPv4ProtocolNumber
		case header.IPv6Version:
			p = header.IPv6ProtocolNumber
		default:
			return true, nil
		}
	}

	d.e.dispatcher.DeliverNetworkPacket(p, pkt)

	return true, nil
}

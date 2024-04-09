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
	"sync/atomic"
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type iovecBuffer struct {
	// buffer is the actual buffer that holds the packet contents. Some contents
	// are reused across calls to pullBuffer if number of requested bytes is
	// smaller than the number of bytes allocated in the buffer.
	buffer buffer.Buffer

	// iovecs are initialized with base pointers/len of the corresponding
	// entries in the views defined above, except when GSO is enabled
	// (skipsVnetHdr) then the first iovec points to a buffer for the vnet header
	// which is stripped before the views are passed up the stack for further
	// processing.
	iovecs []unix.Iovec

	// sizes is an array of buffer sizes for the underlying views. sizes is
	// immutable.
	sizes []int

	// unused: skipsVnetHdr is true if virtioNetHdr is to skipped.
	// skipsVnetHdr bool

	// pulledIndex is the index of the last []byte buffer pulled from the
	// underlying buffer storage during a call to pullBuffers. It is -1
	// if no buffer is pulled.
	pulledIndex int
}

func newIovecBuffer(sizes []int) *iovecBuffer {
	b := &iovecBuffer{
		sizes: sizes,
		// Setting pulledIndex to the length of sizes will allocate all
		// the buffers.
		pulledIndex: len(sizes),
	}
	niov := len(sizes)
	b.iovecs = make([]unix.Iovec, niov)
	return b
}

func (b *iovecBuffer) nextIovecs() []unix.Iovec {
	vnetHdrOff := 0

	var buf buffer.Buffer
	for i, size := range b.sizes {
		if i > b.pulledIndex {
			break
		}
		v := buffer.NewViewSize(size)
		buf.Append(v)
		b.iovecs[i+vnetHdrOff] = unix.Iovec{Base: v.BasePtr()}
		b.iovecs[i+vnetHdrOff].SetLen(v.Size())
	}
	buf.Merge(&b.buffer)
	b.buffer = buf
	b.pulledIndex = -1
	return b.iovecs
}

// pullBuffer extracts the enough underlying storage from b.buffer to hold n
// bytes. It removes this storage from b.buffer, returns a new buffer
// that holds the storage, and updates pulledIndex to indicate which part
// of b.buffer's storage must be reallocated during the next call to
// nextIovecs.
func (b *iovecBuffer) pullBuffer(n int) buffer.Buffer {
	var pulled buffer.Buffer
	c := 0
	// Remove the used views from the buffer.
	pulled = b.buffer.Clone()
	for _, size := range b.sizes {
		b.pulledIndex++
		c += size
		b.buffer.TrimFront(int64(size))
		if c >= n {
			break
		}
	}
	pulled.Truncate(int64(n))
	return pulled
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

	// closed is set to true when fd is closed.
	closed atomic.Bool
}

var _ linkDispatcher = (*readVDispatcher)(nil)

// newReadVDispatcher creates a new linkDispatcher that vector reads packets from
// fd and dispatches them to endpoint e. It assumes ownership of fd but not of e.
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

	d.buf = newIovecBuffer(BufConfig)
	return d, nil
}

func (d *readVDispatcher) stop() {
	d.closed.Store(true)
	d.stopFd.stop()
	// TODO: should close tun-fd before stopFd?
	err := syscall.Close(d.fd)
	log.I("ns: dispatch: stop: fds closed event(%d) tun(%d); err? %v", d.efd, d.fd, err)
}

const abort = false // abort indicates that the dispatcher should stop.
const cont = true   // cont indicates that the dispatcher should continue delivering packets despite an error.

// dispatch reads one packet from the file descriptor and dispatches it.
func (d *readVDispatcher) dispatch() (bool, tcpip.Error) {
	done := d.closed.Load()
	log.V("ns: tun(%d): dispatch: done? %t", d.fd, done)
	if done {
		return abort, new(tcpip.ErrAborted)
	}

	iov := d.buf.nextIovecs()
	if len(iov) == 0 {
		return abort, new(tcpip.ErrBadBuffer)
	}

	n, err := rawfile.BlockingReadvUntilStopped(d.efd, d.fd, iov)

	log.V("ns: tun(%d): dispatch: got(%d bytes), err(%v)", d.fd, n, err)
	if n <= 0 || err != nil {
		if err == nil {
			err = new(tcpip.ErrNoSuchFile)
		}
		return abort, err
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: d.buf.pullBuffer(n),
	})

	var p tcpip.NetworkProtocolNumber
	// hdrSize always zero; unused
	if d.e.hdrSize > 0 {
		hdr, ok := pkt.LinkHeader().Consume(d.e.hdrSize)
		if !ok {
			pkt.DecRef()
			return cont, nil
		}
		p = header.Ethernet(hdr).Type()
	} else {
		// We don't get any indication of what the packet is, so try to guess
		// if it's an IPv4 or IPv6 packet.
		// IP version information is at the first octet, so pulling up 1 byte.
		h, ok := pkt.Data().PullUp(1)
		if !ok {
			log.W("ns: tun(%d): dispatch: no data!", d.fd)
			pkt.DecRef()
			return cont, nil
		}
		switch header.IPVersion(h) {
		case header.IPv4Version:
			p = header.IPv4ProtocolNumber
		case header.IPv6Version:
			p = header.IPv6ProtocolNumber
		default:
			log.W("ns: tun(%d): dispatch: unknown proto!", d.fd)
			pkt.DecRef()
			return cont, nil
		}
	}

	log.V("ns: tun(%d): dispatch: (from-tun) proto(%d) for pkt-id(%d)", d.fd, p, pkt.Hash)

	go func() {
		d.e.InjectInbound(p, pkt)
		pkt.DecRef()
	}()
	return cont, nil
}

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

package netstack

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Adopted from: github.com/google/gvisor/blob/f2b01a6e4/pkg/tcpip/link/fdbased/packet_dispatchers.go

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type iovecBuffer struct {
	// buffer is the actual buffer that holds the packet contents. Some contents
	// are reused across calls to pullBuffer if number of requested bytes is
	// smaller than the number of bytes allocated in the buffer.
	views []*buffer.View

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
		views: make([]*buffer.View, len(sizes)),
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

	for i := range b.views {
		if b.views[i] != nil {
			break
		}
		v := buffer.NewViewSize(b.sizes[i])
		b.views[i] = v
		b.iovecs[i+vnetHdrOff] = unix.Iovec{Base: v.BasePtr()}
		b.iovecs[i+vnetHdrOff].SetLen(v.Size())
	}
	return b.iovecs
}

func (b *iovecBuffer) release() {
	for _, v := range b.views {
		if v != nil {
			v.Release()
			v = nil
		}
	}
}

// pullBuffer extracts the enough underlying storage from b.buffer to hold n
// bytes. It removes this storage from b.buffer, returns a new buffer
// that holds the storage, and updates pulledIndex to indicate which part
// of b.buffer's storage must be reallocated during the next call to
// nextIovecs.
func (b *iovecBuffer) pullBuffer(n int) buffer.Buffer {
	var views []*buffer.View
	c := 0
	// Remove the used views from the buffer.
	for i, v := range b.views {
		c += v.Size()
		if c >= n {
			b.views[i].CapLength(v.Size() - (c - n))
			views = append(views, b.views[:i+1]...)
			break
		}
	}
	for i := range views {
		b.views[i] = nil
	}
	pulled := buffer.Buffer{}
	for i, v := range views {
		if err := pulled.Append(v); err != nil {
			log.W("ns: dispatch: iov: err append view# %d: %v", i, err)
			continue
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
	stopFd              // stopFd is used to signal the dispatcher to stop.
	fd     int          // fd is the file descriptor used to send/receive packets.
	e      *endpoint    // e is the endpoint this dispatcher is attached to.
	buf    *iovecBuffer // buf is the iovec buffer that contains packets.
	closed atomic.Bool  // closed is set to true when fd is closed.
	once   sync.Once    // Ensures stop() is called only once.
	mgr    *supervisor
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
		buf:    newIovecBuffer(BufConfig),
		mgr:    newSupervisor(e),
	}

	d.mgr.start()

	log.I("ns: dispatch: newReadVDispatcher: tun(%d) efd(%d)", fd, d.efd)

	return d, nil
}

// stop stops the dispatcher once. Safe to call multiple times.
func (d *readVDispatcher) stop() {
	defer core.Recover(core.Exit11, "ns.d.stop")

	d.once.Do(func() {
		d.closed.Store(true)
		d.stopFd.stop()
		d.buf.release()
		d.mgr.stop()
		err := syscall.Close(d.fd) // TODO: close tun-fd before stopFd?
		log.I("ns: dispatch: stop: fds closed event(%d) tun(%d); err? %v", d.efd, d.fd, err)
	})
}

const abort = false // abort indicates that the dispatcher should stop.
const cont = true   // cont indicates that the dispatcher should continue delivering packets despite an error.

// dispatch reads one packet from the file descriptor and dispatches it.
func (d *readVDispatcher) dispatch() (bool, tcpip.Error) {
	done := d.closed.Load()
	log.VV("ns: tun(%d): dispatch: done? %t", d.fd, done)
	if done {
		return abort, new(tcpip.ErrAborted)
	}
	if settings.Debug && rand10pc() {
		panic(fmt.Sprintf("ns: tun(%d): dispatch: debug: rand10pc", d.fd))
	}

	iov := d.buf.nextIovecs()
	if len(iov) == 0 {
		return abort, new(tcpip.ErrBadBuffer)
	}

	n, err := rawfile.BlockingReadvUntilStopped(d.efd, d.fd, iov)

	log.VV("ns: tun(%d): dispatch: got(%d bytes), err(%v)", d.fd, n, err)
	if n <= 0 || err != nil {
		if err == nil {
			err = new(tcpip.ErrNoSuchFile)
		}
		return abort, err
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: d.buf.pullBuffer(n),
	})
	defer pkt.DecRef()

	var iseth = d.e.hdrSize > 0 // hdrSize always zero; unused
	if iseth {
		if !d.e.parseHeader(pkt) {
			return abort, new(tcpip.ErrNotPermitted)
		}
		pkt.NetworkProtocolNumber = header.Ethernet(pkt.LinkHeader().Slice()).Type()
	}

	d.mgr.queuePacket(pkt, iseth)
	d.mgr.wakeReady()

	return cont, nil
}

func rand10pc() bool {
	return rand.Intn(999999) < 99999
}

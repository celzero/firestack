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
	"math/rand"
	"net"
	"sync"
	"sync/atomic"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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

// readVDispatcher uses readv() system call to read inbound packets and
// dispatches them.
type readVDispatcher struct {
	fds    *core.Volatile[*fds]
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
	tun, err := newTun(fd)
	if err != nil {
		return nil, err
	}
	d := &readVDispatcher{
		e:   e,
		fds: core.NewVolatile(tun),
		buf: newIovecBuffer(BufConfig),
		mgr: newSupervisor(e, fd),
	}
	d.mgr.start()

	log.I("ns: dispatch: newReadVDispatcher: tun(%d)", fd)
	return d, nil
}

// swap atomically swaps existing fd for this new one.
func (d *readVDispatcher) swap(fd int) error {
	done := d.closed.Load()
	if done {
		return net.ErrClosed
	}

	note := log.I
	f, err := newTun(fd)
	if err != nil {
		note = log.W
	}

	prev := d.fds.Swap(f) // f may be nil
	prev.stop()           // prev may be nil
	d.mgr.swap(fd)        // used for diagnostics only

	note("ns: dispatch: swap: tun(%d => %d); err %v", prev.tun(), fd, err)
	return err
}

// stop stops the dispatcher once. Safe to call multiple times.
func (d *readVDispatcher) stop() {
	defer core.Recover(core.Exit11, "ns.d.stop")

	d.once.Do(func() {
		d.closed.Store(true)
		d.fds.Load().stop()
		d.buf.release()
		d.mgr.stop()
		log.I("ns: dispatch: closed!")
	})
}

const abort = false // abort indicates that the dispatcher should stop.
const cont = true   // cont indicates that the dispatcher should continue delivering packets despite an error.

// dispatch reads one packet from the file descriptor and dispatches it.
func (d *readVDispatcher) dispatch() (bool, tcpip.Error) {
	fds := d.fds.Load()
	if !fds.ok() {
		return abort, new(tcpip.ErrNoSuchFile)
	}

	done := d.closed.Load()
	log.VV("ns: tun(%d): dispatch: done? %t", fds.tun(), done)
	if done {
		return abort, new(tcpip.ErrAborted)
	}

	iov := d.buf.nextIovecs()
	if len(iov) == 0 {
		return abort, new(tcpip.ErrBadBuffer)
	}

	// github.com/google/gvisor/blob/d59375d82/pkg/tcpip/link/fdbased/packet_dispatchers.go#L186
	n, errno := rawfile.BlockingReadvUntilStopped(fds.eve(), fds.tun(), iov)

	log.VV("ns: tun(%d): dispatch: got(%d bytes), err(%v)", fds.tun(), n, errno)
	if n <= 0 || errno != 0 {
		if errno == 0 {
			return abort, new(tcpip.ErrNoSuchFile)
		}
		return abort, tcpip.TranslateErrno(errno)
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

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Adopted from: github.com/google/gvisor/blob/f2b01a6e4/pkg/tcpip/link/fdbased/packet_dispatchers.go

const wrapttl = 5 * time.Second // wrapttl is the time to wait for wrapup() to complete.

// is the dispatcher thread safe?
const threadSafe = false

// bufcfg defines the shape of the vectorised view used to read packets from the NIC.
var bufcfg = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type iovecBuffer struct {
	// serializes access to all members
	sync.Mutex

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
	if threadSafe {
		b.Lock()
		defer b.Unlock()
	}

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
	if threadSafe {
		b.Lock()
		defer b.Unlock()
	}

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
func (b *iovecBuffer) pullBuffer(n int) (pulled buffer.Buffer, ok bool) {
	var views []*buffer.View
	c := 0

	needsUnlock := false
	if threadSafe {
		b.Lock()
		needsUnlock = true
	}
	// Remove the used views from the buffer.
	for i, v := range b.views {
		if v == nil {
			continue
		}
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
	if needsUnlock {
		b.Unlock()
	}

	for i, v := range views {
		if err := pulled.Append(v); err != nil {
			log.W("ns: dispatch: iov: err append view# %d: %v", i, err)
			continue
		}
	}
	ok = pulled.Size() >= int64(n)
	pulled.Truncate(int64(n))
	return
}

// readVDispatcher uses readv() system call to read inbound packets and
// dispatches them.
type readVDispatcher struct {
	e      *endpoint    // e is the endpoint this dispatcher is attached to.
	buf    *iovecBuffer // buf is the iovec buffer that contains packets.
	closed atomic.Bool  // closed is set to true when fd is closed.
	once   sync.Once    // Ensures stop() is called only once.
	mgr    *supervisor
}

var _ linkDispatcher = (*readVDispatcher)(nil)

// newReadVDispatcher creates a new linkDispatcher that vector reads packets from
// fd and dispatches them to endpoint e. It assumes ownership of fd but not of e.
func newReadVDispatcher(f *fds, e *endpoint) (linkDispatcher, error) {
	d := &readVDispatcher{
		e:   e,
		buf: newIovecBuffer(bufcfg),
		mgr: newSupervisor(e, f.tun()),
	}
	d.mgr.start()

	log.I("ns: dispatch: newReadVDispatcher: tun(%s)", f)
	return d, nil
}

// swap atomically swaps existing fd for this new one.
// On error, it closes fd.
func (d *readVDispatcher) prepare(f *fds) {
	if !d.closed.Load() {
		d.mgr.note(f.tun()) // used for diagnostics only
	}
}

// stop stops the dispatcher once. Safe to call multiple times.
func (d *readVDispatcher) stop() {
	d.once.Do(func() {
		d.closed.Store(true)
		d.mgr.stop()
		log.I("ns: dispatch: closed!")
	})
}

const abort = false // abort indicates that the dispatcher should stop.
const cont = true   // cont indicates that the dispatcher should continue delivering packets despite an error.

// dispatch reads packets from the current file descriptor in d.fds and dispatches it to netstack.
func (d *readVDispatcher) dispatch(fd *fds) (bool, tcpip.Error) {
	return d.io(fd)
}

// wrapup reads packets from fds and dispatches it to netstack
// and closes fds on error or on timeout. If settings.Loopingback is true,
// it closes fds immediately. Must be called in a goroutine.
func (d *readVDispatcher) wrapup(fds *fds, noMoreThan30s time.Duration) {
	if !fds.ok() { // fds may be nil
		return
	}
	defer fds.stop()

	// Loopback is set to true when VPN is in lockdown mode (block connections
	// without vpn). It is observed that by closing the previous tun after delay
	// results in "connection was reset" errors in netstack's TCP handler, which
	// only go away if the tunnel is recreated (via stop/start or pause/unpause).
	// This behaviour is seen when the device either connects to internet after
	// quite a while or the device switches to a new network (on Android 14+).
	if !threadSafe || settings.Loopingback.Load() {
		log.I("ns: tun(%d): wrapup: immediate (loopback)", fds.tun())
		return
	}

	awaited := core.Await(func() {
		log.I("ns: tun(%d): drain: start w timeout in %s", fds.tun(), core.FmtPeriod(noMoreThan30s))
		for {
			cont, err := d.io(fds)
			if fd := fds.tun(); !cont {
				log.W("ns: tun(%d): drain: exit; err? %v", fd, err)
				return
			} else if err != nil {
				log.W("ns: tun(%d): drain: continue on err: %v", fd, err)
			} // else: continue draining
		}
	}, min(30*time.Second, noMoreThan30s))

	logei(!awaited)("ns: tun(%d): drain: timeout!", fds.tun())
}

// io reads packets from fds and dispatches it to netstack.
// not thread safe (see: threadSafe).
func (d *readVDispatcher) io(fds *fds) (bool, tcpip.Error) {
	done := d.closed.Load()
	if done {
		log.W("ns: tun(%d): dispatch: done! %t", fds.tun(), done)
		d.buf.release() // not thread safe
		return abort, new(tcpip.ErrAborted)
	}

	if fds == nil || !fds.ok() { // nil check for nilaway
		log.W("ns: tun(%d): dispatch: fd closed or invalid!", fds.tun())
		return abort, new(tcpip.ErrNoSuchFile)
	}

	iov := d.buf.nextIovecs() // not thread safe
	if len(iov) == 0 {
		log.E("ns: tun(%d): dispatch: iov == 0", fds.tun())
		return abort, new(tcpip.ErrBadBuffer)
	}

	if settings.Debug {
		log.VV("ns: tun(%d): dispatch: start; iov: %d", fds.tun(), len(iov))
	}

	start := time.Now()

	// github.com/google/gvisor/blob/d59375d82/pkg/tcpip/link/fdbased/packet_dispatchers.go#L186
	n, errno := rawfile.BlockingReadvUntilStopped(fds.eve(), fds.tun(), iov)

	fds.lastRead.Store(time.Now().UnixMilli()) // update last read time

	if settings.Debug {
		log.VV("ns: tun(%d): dispatch: after %s, got(iov: %d / bytes: %d / tot: %d), err(%v)",
			fds.tun(), core.FmtPeriod(time.Since(start)), len(iov), n, fds.read.Load(), errno)
	}

	if n <= 0 || errno != 0 {
		if errno == 0 {
			return abort, new(tcpip.ErrNoSuchFile)
		}
		return abort, tcpip.TranslateErrno(errno)
	}

	fds.read.Add(int64(n)) // update read bytes

	b, ok := d.buf.pullBuffer(n) // not thread safe
	if !ok {
		log.E("ns: tun(%d): dispatch: pullBuffer err; n: %d", fds.tun(), n)
		return abort, new(tcpip.ErrBadBuffer)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: b,
	})
	defer pkt.DecRef()

	var iseth = d.e.hdrSize > 0 // hdrSize always zero; unused
	if iseth {
		if !d.e.parseHeader(pkt) {
			return abort, new(tcpip.ErrNotPermitted)
		}
		pkt.NetworkProtocolNumber = header.Ethernet(pkt.LinkHeader().Slice()).Type()
	}

	start = time.Now()
	if settings.Debug {
		log.VV("ns: tun(%d): dispatch: pkt sz: %d", fds.tun(), pkt.Size())
	}

	d.mgr.queuePacket(pkt, iseth)
	d.mgr.wakeReady()

	if settings.Debug {
		log.VV("ns: tun(%d): dispatch: done after %s; pkt sz: %d",
			fds.tun(), core.FmtPeriod(time.Since(start)), pkt.Size())
	}

	return cont, nil
}

func rand10pc() bool {
	return rand.Intn(999999) < 99999
}

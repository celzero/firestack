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

// Package netstack provides the implemention of data-link layer endpoints
// backed by boundary-preserving file descriptors (e.g., TUN devices,
// seqpacket/datagram sockets).
//
// Adopted from: github.com/google/gvisor/blob/f33d034/pkg/tcpip/link/fdbased/endpoint.go
// since fdbased isn't built when building for android (it is only built for linux).
package netstack

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.InjectableLinkEndpoint = (*endpoint)(nil)
var _ stack.LinkEndpoint = (*endpoint)(nil)
var _ stack.LinkEndpoint = (*linkFdSwap)(nil)
var _ FdSwapper = (*linkFdSwap)(nil)

// placeholder FD for whenever existing FD wrapped in struct fds is closed.
const invalidfd int = -1

// Should WritePackets return NoSuchFile error if the fd is invalid?
const errorOnInvalidFD = false

// wrapttl is the time to wait for the dispatcher to wrap up (close a previous FD).
const waitttl = wrapttl

type FdSwapper interface {
	// Cur returns the current FD.
	Cur() int
	// Swap closes existing FDs; uses new fd.
	Swap(fd int) error
	// Dispose closes all existing FDs.
	Dispose() error
	// Stat returns csv (fd, age, read, written, lastRead, lastWrite) stats.
	Stat() string
}

type SeamlessEndpoint interface {
	stack.LinkEndpoint
	FdSwapper
}

// linkDispatcher reads packets from the link FD and dispatches them to the
// NetworkDispatcher.
type linkDispatcher interface {
	stop()
	prepare(fd *fds)
	dispatch(fd *fds) (bool, tcpip.Error)
	wrapup(prev *fds, ttl time.Duration)
}

type endpoint struct {
	sync.RWMutex
	// fds is the set of file descriptors each identifying one inbound/outbound
	// channel. The endpoint will dispatch from all inbound channels as well as
	// hash outbound packets to specific channels based on the packet hash.
	fds *core.Volatile[*fds]

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu atomic.Uint32

	// hdrSize specifies the link-layer header size. If set to 0, no header
	// is added/removed; otherwise an ethernet header is used.
	hdrSize int

	// addr is the address of the endpoint.
	addr tcpip.LinkAddress

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// dispatches packets from the link FD (tun device)
	// to the network stack. Protected by the endpoint's mutex.
	inboundDispatcher linkDispatcher
	// the nic this endpoint is attached to. Protected by the endpoint's mutex.
	dispatcher stack.NetworkDispatcher

	// wg keeps track of running goroutines.
	wg sync.WaitGroup

	// maxSyscallHeaderBytes has the same meaning as
	// Options.MaxSyscallHeaderBytes.
	maxSyscallHeaderBytes uintptr

	// writevMaxIovs is the maximum number of iovecs that may be passed to
	// rawfile.NonBlockingWriteIovec, as possibly limited by
	// maxSyscallHeaderBytes. (No analogous limit is defined for
	// rawfile.NonBlockingSendMMsg, since in that case the maximum number of
	// iovecs also depends on the number of mmsghdrs. Instead, if sendBatch
	// encounters a packet whose iovec count is limited by
	// maxSyscallHeaderBytes, it falls back to writing the packet using writev
	// via WritePacket.)
	writevMaxIovs int
}

// Options specify the details about the fd-based endpoint to be created.
type Options struct {
	// FDs is a set of FDs used to read/write packets.
	FDs []int

	// MTU is the mtu to use for this endpoint.
	MTU uint32

	// EthernetHeader if true, indicates that the endpoint should read/write
	// ethernet frames instead of IP packets.
	EthernetHeader bool

	// Address is the link address for this endpoint. Only used if
	// EthernetHeader is true.
	Address tcpip.LinkAddress

	// SaveRestore if true, indicates that this NIC capability set should
	// include CapabilitySaveRestore
	SaveRestore bool

	// DisconnectOk if true, indicates that this NIC capability set should
	// include CapabilityDisconnectOk.
	DisconnectOk bool

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	RXChecksumOffload bool

	// If MaxSyscallHeaderBytes is non-zero, it is the maximum number of bytes
	// of struct iovec, msghdr, and mmsghdr that may be passed by each host
	// system call.
	MaxSyscallHeaderBytes int
}

// New creates a new fd-based endpoint.
//
// Makes fd non-blocking, but does not take ownership of fd, which must remain
// open for the lifetime of the returned endpoint (until after the endpoint has
// stopped being using and Wait returns).
func NewFdbasedInjectableEndpoint(opts *Options) (SeamlessEndpoint, error) {
	caps := stack.LinkEndpointCapabilities(0)
	if opts.RXChecksumOffload {
		caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		caps |= stack.CapabilityTXChecksumOffload
	}

	hdrSize := 0
	if opts.EthernetHeader {
		hdrSize = header.EthernetMinimumSize
		caps |= stack.CapabilityResolutionRequired
	}

	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	if opts.DisconnectOk {
		caps |= stack.CapabilityDisconnectOk
	}

	if len(opts.FDs) == 0 {
		return nil, fmt.Errorf("opts.FD is empty, at least one FD must be specified")
	}

	if opts.MaxSyscallHeaderBytes < 0 {
		return nil, fmt.Errorf("opts.MaxSyscallHeaderBytes is negative")
	}

	e := &endpoint{
		mtu:     atomic.Uint32{},
		fds:     core.NewVolatile(invalidFds),
		caps:    caps,
		addr:    opts.Address,
		hdrSize: hdrSize,
		// MaxSyscallHeaderBytes remains unused
		maxSyscallHeaderBytes: uintptr(opts.MaxSyscallHeaderBytes),
		writevMaxIovs:         rawfile.MaxIovs,
	}
	if e.maxSyscallHeaderBytes != 0 {
		if max := int(e.maxSyscallHeaderBytes / rawfile.SizeofIovec); max < e.writevMaxIovs {
			e.writevMaxIovs = max
		}
	}

	// Create per channel dispatchers; usually only one.
	if len(opts.FDs) != 1 {
		return nil, fmt.Errorf("len(opts.FDs) = %d, expected 1", len(opts.FDs))
	}

	e.SetMTU(opts.MTU)

	if err := e.Swap(opts.FDs[0]); err != nil {
		return nil, err
	}

	return e, nil
}

func createInboundDispatcher(e *endpoint, f *fds) (linkDispatcher, error) {
	// By default use the readv() dispatcher as it works with all kinds of
	// FDs (tap/tun/unix domain sockets and af_packet).
	d, err := newReadVDispatcher(f, e)
	if err != nil {
		return nil, fmt.Errorf("newReadVDispatcher(%s, %+v) = %v", f, e, err)
	}
	return d, nil
}

func (e *endpoint) Cur() int {
	return e.fd()
}

func (e *endpoint) Stat() string {
	fds := e.fds.Load()
	if fds == nil {
		// fd, age, read, written, lastRead, lastWrite
		return "-1,0,0,0,0,0"
	}

	t := time.Now()
	if death := fds.death.Load(); death > 0 {
		t = time.UnixMilli(death)
	}

	age := t.Sub(time.UnixMilli(fds.since.Load()))

	return fmt.Sprintf("%d,%s,%d,%d,%s,%s",
		fds.tunFd, // f.tun() returns invalidfd if f.tunFd is closed
		core.FmtPeriod(age),
		fds.read.Load(),
		fds.written.Load(),
		core.FmtUnixMillisAsPeriod(fds.lastRead.Load()),
		core.FmtUnixMillisAsPeriod(fds.lastWrite.Load()))
}

func (e *endpoint) Dispose() (err error) {
	e.Lock()
	defer e.Unlock()

	prevfd := e.fds.Swap(invalidFds) // prevfd may be invalidfd
	if !prevfd.ok() {
		log.W("ns: tun: Dispose: invalid prevfd")
		return nil
	}

	if e.inboundDispatcher == nil {
		log.W("ns: tun: Dispose: no inbound dispatcher")
		// nothing to do
		return nil
	}
	// e.inboundDispatcher.prepare() will not close prevfd
	// dispatchLoop() will auto-exit on invalidfd
	core.Go("ns.dispose.wrapup", func() { e.inboundDispatcher.wrapup(prevfd, wrapttl) })
	e.inboundDispatcher.prepare(invalidFds)

	return nil
}

// Implements Swapper.
func (e *endpoint) Swap(fd int) (err error) {
	e.Lock()
	defer e.Unlock()

	f, err := newTun(fd) // fd may be invalid (ex: -1)
	if err != nil {
		err = log.EE("ns: tun: swap: (%d) err: %v / %v; using invalidfd", fd, err)
	}

	prevfd := e.fds.Swap(f) // commence WritePackets() on fd

	log.D("ns: tun: swap: fd %s => %d; err? %v", prevfd, fd, err)

	if e.inboundDispatcher == nil { // prevfd must be 0 value if inbound is nil
		prevfd.stop() // prevfd may be invalid
		e.inboundDispatcher, err = createInboundDispatcher(e, f)
	} else {
		// closes prevfd, which may be invalidfd
		core.Go("ns.swap.wrapup", func() { e.inboundDispatcher.wrapup(prevfd, wrapttl) })
		e.inboundDispatcher.prepare(f)
	}

	hasDispatcher := e.dispatcher != nil
	if err == nil && hasDispatcher { // attached?
		log.I("ns: tun: (%s => %d) swap: restart looper %t for new fd",
			prevfd, fd, hasDispatcher)
		go dispatchLoop(e.inboundDispatcher, f, &e.wg)
	} else {
		log.E("ns: tun: (%s => %d) swap: no dispatcher? %t for new fd; err %v",
			prevfd, fd, !hasDispatcher, err)
	}
	return
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	log.D("ns: attaching nic... %t", dispatcher != nil)

	e.Lock()
	defer e.Unlock()

	rx := e.inboundDispatcher

	fds := e.fds.Load()
	fd := fds.tun()

	attach := dispatcher != nil   // nil means the NIC is being removed.
	pipe := rx != nil             // nil means there's no read dispatcher.
	exists := e.dispatcher != nil // nil means the NIC is already detached.

	// Attach is called when the NIC is being created and then enabled.
	// stack.CreateNIC -> nic.newNIC -> ep.Attach
	if dispatcher == nil && e.dispatcher != nil {
		log.I("ns: tun(%d): attach: detach dispatcher (and inbound? %t)", fd, pipe)
		allLoopersExited := true
		if rx != nil {
			go rx.stop() // avoid mutex
			fds.stop()

			allLoopersExited = e.wait(waitttl) // on all inboundDispatcher w/ mutex locked?
		}
		e.dispatcher = nil
		e.inboundDispatcher = nil // rx
		e.fds.Store(invalidFds)
		logei(!allLoopersExited)("ns: tun(%d): attach: done detaching dispatcher; all loopers done? %t",
			fd, allLoopersExited)
		return
	}

	if dispatcher != nil && e.dispatcher == nil {
		log.I("ns: tun(%d): attach: new dispatcher & looper", fd)
		e.dispatcher = dispatcher
		if e.inboundDispatcher == nil && fds.ok() { // unlikely
			var err error
			e.inboundDispatcher, err = createInboundDispatcher(e, fds)
			logeif(err)("ns: tun(%d): attach: just-in-time createInboundDispatcher; err? %v", fd, err)
			rx = e.inboundDispatcher
		}
		go dispatchLoop(rx, fds, &e.wg)
		return
	}

	if dispatcher != nil {
		log.W("ns: tun(%d): attach: discard? %t; but switch to new anyway", fd, exists)
		e.dispatcher = dispatcher
		return
	}

	log.W("ns: tun(%d): attach: discard? %t; hadDispatcher? %t hadInbound? %t", fd, exists, attach, pipe)
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	d, _ := e.getDispatcher()
	return d != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu.Load()
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// MaxHeaderLength returns the maximum size of the link-layer header.
func (e *endpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// LinkAddress returns the link address of this endpoint.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	e.RLock()
	defer e.RUnlock()
	return e.addr
}

// Wait implements stack.LinkEndpoint.Wait. It waits for the endpoint to stop
// reading from its FD.
func (e *endpoint) Wait() {
	e.wg.Wait()
}

func (e *endpoint) wait(d time.Duration) bool {
	// wait on e.Wait() until ttl expires
	return core.Await(func() { e.Wait() }, d)
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *endpoint) AddHeader(pkt *stack.PacketBuffer) {
	if e.hdrSize > 0 && pkt != nil {
		// Add ethernet header if needed.
		eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
		eth.Encode(&header.EthernetFields{
			SrcAddr: pkt.EgressRoute.LocalLinkAddress,
			DstAddr: pkt.EgressRoute.RemoteLinkAddress,
			Type:    pkt.NetworkProtocolNumber,
		})
	}
}

func (e *endpoint) parseHeader(pkt *stack.PacketBuffer) bool {
	if pkt == nil {
		return false
	}
	_, ok := pkt.LinkHeader().Consume(e.hdrSize)
	return ok
}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (e *endpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	if pkt == nil {
		return false
	}
	if e.hdrSize > 0 {
		return e.parseHeader(pkt)
	}
	return true
}

// fd returns the file descriptor associated with the endpoint.
func (e *endpoint) fd() int {
	return e.fds.Load().tun()
}

// writePackets writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
// Way more simplified than og impl, ref: github.com/google/gvisor/issues/7125
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// Preallocate to avoid repeated reallocation as we append to batch.
	// batchSz is 47 because when SWGSO is in use then a single 65KB TCP
	// segment can get split into 46 segments of 1420 bytes and a single 216
	// byte segment.
	const batchSz = 47
	fds := e.fds.Load()
	fd := fds.tun() // if closed, returns invalidfd

	if fd == invalidfd {
		log.E("ns: tun(-1): WritePackets (to tun): fd invalid (pkts: %d)", pkts.Len())
		if errorOnInvalidFD {
			return 0, &tcpip.ErrNoSuchFile{}
		}
		return 0, nil
	}

	batch := make([]unix.Iovec, 0, batchSz)
	packets, written := 0, 0
	total := pkts.Len()

	defer func() {
		fds.written.Add(int64(written)) // update written bytes
		fds.lastWrite.Store(time.Now().UnixMilli())
	}()

	for _, pkt := range pkts.AsSlice() {
		views := pkt.AsSlices()
		numIovecs := len(views)
		if len(batch)+numIovecs > rawfile.MaxIovs {
			// writes in to fd, up to len(batch) not cap(batch)
			if errno := rawfile.NonBlockingWriteIovec(fd, batch); errno != 0 {
				log.W("ns: tun(%d): WritePackets (to tun): err(%v), sent(%d)/total(%d)", fd, errno, written, total)
				return written, tcpip.TranslateErrno(errno)
			}
			// mark processed packets as written
			written += packets
			// truncate batch
			batch = batch[:0]
			// reset processed packets count
			packets = 0
		}
		for _, v := range views {
			batch = rawfile.AppendIovecFromBytes(batch, v, rawfile.MaxIovs)
		}
		packets += 1
	}
	if len(batch) > 0 {
		if errno := rawfile.NonBlockingWriteIovec(fd, batch); errno != 0 {
			log.W("ns: tun(%d): WritePackets (to tun): err(%v), sent(%d)/total(%d)", fd, errno, packets, total)
			return written, tcpip.TranslateErrno(errno)
		}
		written += packets
	}

	log.VV("ns: tun(%d): WritePackets (to tun): written(%d)/total(%d)", fd, written, total)
	return written, nil
}

/*
func (e *endpoint) notifyRestart() {
	// deferred fns here should not end up calling the caller of notifyRestart to avoid
	// infinite recursion (callerFn -> someotherFn -> panic -> notifyRestart -> callerFn)
	// defer e.Attach(nil)
	log.U("Network stopped; restart the app")
}
*/

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack (linkDispatcher). Must be run as a goroutine.
func dispatchLoop(inbound linkDispatcher, f *fds, wg *sync.WaitGroup) tcpip.Error {
	// defer core.RecoverFn("ns.e.dispatch", e.notifyRestart)
	defer core.Recover(core.Exit11, "ns.e.dispatch")

	wg.Add(1)
	defer wg.Done()

	if inbound == nil || core.IsNil(inbound) {
		defer f.stop()
		log.W("ns: tun(%d): dispatchLoop: inbound nil", f.tun())
		return &tcpip.ErrUnknownDevice{}
	}

	start := time.Now()
	log.I("ns: tun(%d): dispatchLoop: start", f.tun())
	for {
		cont, err := inbound.dispatch(f)
		if err != nil {
			logei(cont)("ns: tun(%d): dispatchLoop: dur: %s; continue? %t; err: %v",
				f.tun(), core.FmtTimeAsPeriod(start), cont, err)
		}
		if !cont {
			defer f.stop()
			return err
		} // else: continue dispatching

	}
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	if e.hdrSize > 0 {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}

func (e *endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.Lock()
	defer e.Unlock()
	e.addr = addr
}

func (e *endpoint) SetMTU(mtu uint32) {
	e.mtu.Store(mtu)
}

func (e *endpoint) getDispatcher() (stack.NetworkDispatcher, *fds) {
	e.RLock()
	defer e.RUnlock()
	return e.dispatcher, e.fds.Load()
}

// InjectInbound ingresses a netstack-inbound packet.
func (e *endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d, fds := e.getDispatcher()
	fd := fds.tun()
	log.VV("ns: tun(%d): inject-inbound (from tun) %d", fd, protocol)
	if d != nil && pkt != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	} else {
		log.W("ns: tun(%d): inject-inbound (from tun) %d pkt?(%t) dropped: endpoint not attached", fd, protocol, pkt != nil)
	}
}

// Unused: InjectOutobund implements stack.InjectableEndpoint.InjectOutbound.
// InjectOutbound egresses a tun-inbound packet.
func (e *endpoint) InjectOutbound(dest tcpip.Address, packet *buffer.View) tcpip.Error {
	f := e.fds.Load()
	fd := f.tun()

	if !f.ok() {
		log.E("ns: tun(%d): inject-outbound (to tun) to dst(%v): endpoint not attached", fd, dest)
		if errorOnInvalidFD {
			return &tcpip.ErrUnknownDevice{}
		}
		return nil // nothing to do
	}

	b := packet.AsSlice()
	sz := int64(len(b))
	defer f.written.Add(sz) // update written bytes
	defer f.lastWrite.Store(time.Now().UnixMilli())

	log.VV("ns: tun(%d): inject-outbound (to tun) to dst(%v) sz(%d)", fd, dest, sz)

	errno := rawfile.NonBlockingWrite(fd, b)
	return tcpip.TranslateErrno(errno)
}

// Close implements stack.LinkEndpoint.
func (e *endpoint) Close() {
	log.W("ns: tun(%d): Close!", e.fd())
	e.Attach(nil)
}

// SetOnCloseAction implements stack.LinkEndpoint.
func (*endpoint) SetOnCloseAction(func()) {}

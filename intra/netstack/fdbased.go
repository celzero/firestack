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
	"syscall"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.InjectableLinkEndpoint = (*endpoint)(nil)
var _ stack.LinkEndpoint = (*endpoint)(nil)
var _ stack.LinkEndpoint = (*sniff)(nil)
var _ Swapper = (*sniff)(nil)

const invalidfd int = -1

type Swapper interface {
	// Swap closes existing FDs; uses new fd and mtu.
	Swap(fd, mtu int) error
	// Dispose closes all existing FDs.
	Dispose() error
}

type SeamlessEndpoint interface {
	stack.LinkEndpoint
	Swapper
}

// linkDispatcher reads packets from the link FD and dispatches them to the
// NetworkDispatcher.
type linkDispatcher interface {
	stop()
	swap(fd int) error
	dispatch() (bool, tcpip.Error)
}

type endpoint struct {
	sync.RWMutex
	// fds is the set of file descriptors each identifying one inbound/outbound
	// channel. The endpoint will dispatch from all inbound channels as well as
	// hash outbound packets to specific channels based on the packet hash.
	fds *core.Volatile[int] // int

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
		fds:     core.NewVolatile[int](invalidfd),
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

	if err := e.Swap(opts.FDs[0], int(opts.MTU)); err != nil {
		return nil, err
	}

	return e, nil
}

func createInboundDispatcher(e *endpoint, fd int) (linkDispatcher, error) {
	// By default use the readv() dispatcher as it works with all kinds of
	// FDs (tap/tun/unix domain sockets and af_packet).
	d, err := newReadVDispatcher(fd, e)
	if err != nil {
		return nil, fmt.Errorf("newReadVDispatcher(%d, %+v) = %v", fd, e, err)
	}
	return d, nil
}

func (e *endpoint) Dispose() (err error) {
	if e.fds == nil {
		log.W("ns: tun: Dispose: fds nil")
		return nil
	}
	prevfd := e.fds.Swap(invalidfd) // prevfd may be invalidfd
	if prevfd == invalidfd {
		log.W("ns: tun: Dispose: prevfd invalid")
		return nil
	}

	e.Lock()
	defer e.Unlock()
	if e.inboundDispatcher != nil {
		// e.dispatchLoop() will auto-exit due to invalidfd
		err = e.inboundDispatcher.swap(invalidfd)
	}

	return
}

// Implements Swapper.
func (e *endpoint) Swap(fd, mtu int) (err error) {
	e.SetMTU(uint32(mtu))

	if err = unix.SetNonblock(fd, true); err != nil {
		clos(fd)
		return fmt.Errorf("unix.SetNonblock(%v) failed: %v", fd, err)
	}

	prevfd := e.fds.Swap(fd) // commence WritePackets() on fd

	log.D("ns: swapping tun... fd: %d => %d, mtu: %d", prevfd, fd, mtu)

	e.Lock()
	defer e.Unlock()
	if e.inboundDispatcher == nil { // prevfd must be 0 value if inbound is nil
		e.inboundDispatcher, err = createInboundDispatcher(e, fd)
	} else {
		err = e.inboundDispatcher.swap(fd) // always closes prevfd
		// todo: on err != nil e.inboundDispatcher = nil?
	}

	hasDispatcher := e.dispatcher != nil
	if err == nil && hasDispatcher { // attached?
		go e.dispatchLoop(e.inboundDispatcher)
	} else {
		log.W("ns: tun(%d => %d): Swap: no dispatcher? %t for new fd; err %v", prevfd, fd, !hasDispatcher, err)
	}
	return
}

func clos(fd int) {
	if fd > 0 || fd != invalidfd {
		_ = syscall.Close(fd)
	}
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	log.D("ns: attaching nic... %t", dispatcher != nil)

	e.Lock()
	defer e.Unlock()

	rx := e.inboundDispatcher
	fd := e.fd()
	attach := dispatcher != nil   // nil means the NIC is being removed.
	pipe := rx != nil             // nil means there's no read dispatcher.
	exists := e.dispatcher != nil // nil means the NIC is already detached.
	// Attach is called when the NIC is being created and then enabled.
	// stack.CreateNIC -> nic.newNIC -> ep.Attach
	if dispatcher == nil && e.dispatcher != nil {
		log.I("ns: tun(%d): attach: detach dispatcher (and inbound? %t)", fd, pipe)
		if rx != nil {
			go rx.stop() // avoid mutex
			e.Wait()     // on all inboundDispatcher w/ mutex locked?
		}
		e.dispatcher = nil
		e.inboundDispatcher = nil
		e.fds = nil
		log.I("ns: tun(%d): attach: done detaching dispatcher", fd)
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		log.I("ns: tun(%d): attach: attach new dispatcher", fd)
		e.dispatcher = dispatcher
		go e.dispatchLoop(rx)
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
	return e.getDispatcher() != nil
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

func logPacketIfNeeded(dir sniffer.Direction, pkt *stack.PacketBuffer) {
	if pkt == nil {
		return
	}
	protocol := pkt.NetworkProtocolNumber
	if sniffer.LogPackets.Load() == 1 {
		sniffer.LogPacket("rdnspcap", dir, protocol, pkt)
	}
}

// fd returns the file descriptor associated with the endpoint.
func (e *endpoint) fd() int {
	if fd := e.fds.Load(); fd > 0 {
		return fd
	}
	return invalidfd
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
	fd := e.fd()         // may have been closed
	if fd == invalidfd { // unlikely; panic instead?
		log.E("ns: tun(-1): WritePackets (to tun): fd invalid")
		return 0, &tcpip.ErrNoSuchFile{}
	}
	batch := make([]unix.Iovec, 0, batchSz)
	packets, written := 0, 0
	total := pkts.Len()
	for _, pkt := range pkts.AsSlice() {
		logPacketIfNeeded(sniffer.DirectionSend, pkt)
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

func (e *endpoint) notifyRestart() {
	// deferred fns here should not end up calling the caller of notifyRestart to avoid
	// infinite recursion (callerFn -> someotherFn -> panic -> notifyRestart -> callerFn)
	// defer e.Attach(nil)
	log.U("Network stopped; restart the app")
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack. Must be run as a goroutine.
func (e *endpoint) dispatchLoop(inbound linkDispatcher) tcpip.Error {
	// defer core.RecoverFn("ns.e.dispatch", e.notifyRestart)
	defer core.Recover(core.Exit11, "ns.e.dispatch")

	e.wg.Add(1)
	defer e.wg.Done()

	fd := e.fd()
	if inbound == nil || core.IsNil(inbound) {
		log.W("ns: tun(%d): dispatchLoop: inbound nil", fd)
		return &tcpip.ErrUnknownDevice{}
	}

	log.I("ns: tun(%d): dispatchLoop: start", fd)
	for {
		cont, err := inbound.dispatch()
		if err != nil || !cont {
			log.W("ns: tun(%d): dispatchLoop: exit; err %v", fd, err)
			return err
		}
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

func (e *endpoint) getDispatcher() stack.NetworkDispatcher {
	e.RLock()
	defer e.RUnlock()
	return e.dispatcher
}

// InjectInbound ingresses a netstack-inbound packet.
func (e *endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	logPacketIfNeeded(sniffer.DirectionRecv, pkt)
	d := e.getDispatcher()
	fd := e.fd()
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
	fd := e.fd()
	log.VV("ns: tun(%d): inject-outbound (to tun) to dst(%v)", fd, dest)
	// TODO: e.logPacketIfNeeded(sniffer.DirectionSend, packet)
	errno := rawfile.NonBlockingWrite(fd, packet.AsSlice())
	return tcpip.TranslateErrno(errno)
}

// Close implements stack.LinkEndpoint.
func (e *endpoint) Close() {
	log.W("ns: tun(%d): Close!", e.fd())
	e.Attach(nil)
}

// SetOnCloseAction implements stack.LinkEndpoint.
func (*endpoint) SetOnCloseAction(func()) {}

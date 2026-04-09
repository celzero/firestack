// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package log

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// memHdrSize is the byte-size of the header embedded at the start of each
	// memfd region: a single uint64 (little-endian) holding the number of
	// complete line slots written into the buffer.
	memHdrSize = 8

	// memFlushInterval is the maximum time to hold log lines in the active
	// buffer before force-flushing to the reader.
	memFlushInterval = 2500 * time.Millisecond
)

// overwriteOnFull controls the behaviour when the active buffer is full and
// the other buffer has not been consumed yet.
// If true, slotIdx wraps to 0, overwriting the oldest slots in the active
// buffer (ring-within-buffer).
// If false, log lines are silently discarded.
const overwriteOnFull = true

// buffer: (pageSize / slotSize) slots * memSlotSize bytes each.
// On a 4 KiB page: 4096 / 800 = 5 slots => memBufSize = 8 + 5*800 = 4008 B ≈ 1 page.
// memBufSize is the total region passed to Ftruncate/Mmap.
var (
	nofpages    = 8
	memSlotSize = charsPerLine                                // 800 bytes per slot
	memNumSlots = nofpages * unix.Getpagesize() / memSlotSize // slots that fit in one page
	memBufSize  = memHdrSize + memNumSlots*memSlotSize        // ≈ 1 page
)

// mcbuf is a fixed-slot shared-memory region backed by a memfd.
//
// Buffer layout (memBufSize bytes):
//
//	[0 : 8]                                 uint64 LE: number of valid slots (atomic)
//	[8 : 8+memSlotSize]                     slot 0 (memSlotSize bytes, newline-terminated)
//	[8+memSlotSize : 8+2*memSlotSize]       slot 1
//	... (memNumSlots total) ...
//
// Each slot is exactly memSlotSize (charsPerLine = 800) bytes.  The writer
// zero-fills the tail of every slot after the newline so readers can use
// either strnlen or a fixed-width read. The header count is the number of
// fully written slots; it is updated after every slot write.
//
// The Go writer owns writes; after consume returns the Go side resets the buffer.
type mcbuf struct {
	fd   *os.File // memfd; Go retains ownership so the GC keeps the fd open
	data []byte   // mmap region (PROT_READ|PROT_WRITE, MAP_SHARED)
}

// setCountLocked atomically stores n as the number of fully written slots.
func (b *mcbuf) setCountLocked(n uint64) {
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&b.data[0])), n)
}

// close releases the mmap region and closes the memfd.
func (b *mcbuf) close() {
	if b == nil {
		return
	}
	if b.data != nil {
		_ = unix.Munmap(b.data)
		b.data = nil
	}
	if b.fd != nil {
		_ = b.fd.Close()
		b.fd = nil
	}
}

// Memconsole is a double-buffered, zero-copy log console. Log lines are
// written into one of two page-aligned shared-memory regions. When
// a buffer fills up the reader is signalled via Drain() and the writer
// flips to the other buffer.
//
// The Go side is always the writer. The reader may live in another runtime.
//
// When the active buffer fills up and draining[other]=true: the write either
// wraps slotIdx=0 (overwriteOnFull=true, ring-within-buffer) and increments
// Drops, or is discarded (overwriteOnFull=false) and Drops is incremented.
// Once consume returns on the other buffer it is available for the next flip.
//
// periodicFlush: if the other buffer is draining when the ticker fires, the
// ticker re-arms itself for another memFlushInterval rather than stacking
// concurrent consume calls.
type Memconsole struct {
	mu sync.Mutex // protects following fields

	bufs      [2]*mcbuf
	active    int            // 0 or 1: index of the buffer being written to
	slotIdx   int            // next slot index to write into [0, memNumSlots)
	lastFlush time.Time      // wall time of the most recent consume initiation
	reader    MemReader      // installed via SetReader
	draining  [2]atomic.Bool // true while Drain() is executing for bufs[i]
	drops     atomic.Uint64
	ticking   atomic.Bool // true while a lazy ticker goroutine is running
	closed    atomic.Bool
}

var _ Console = (*Memconsole)(nil)
var _ io.Closer = (*Memconsole)(nil)

// hasmemfd probes whether the kernel supports memfd_create.
func hasmemfd() error {
	fd, err := unix.MemfdCreate("probe", unix.MFD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("log: memfd: unsupported: %w", err)
	}
	_ = unix.Close(fd)
	return nil
}

// NewMemoryBased creates a Memconsole backed by page-aligned memfd regions.
// Returns an error if the kernel does not support memfd_create (Linux < 3.17)
// or if any syscall fails.
//
// The caller must close mc when done.  FDs passed via LogMem should be
// dup(2)'d by the receiver before use.
func NewMemoryBased() (mc *Memconsole, err error) {
	if err = hasmemfd(); err != nil {
		return nil, err
	}

	mc = &Memconsole{}

	for i := range 2 {
		var mfd int
		mfd, err = unix.MemfdCreate(fmt.Sprintf("mlogfd%d", i), unix.MFD_CLOEXEC)
		if err != nil {
			mc.Close()
			return nil, fmt.Errorf("log: memfd: [%d] create: %w", i, err)
		}
		if err = unix.Ftruncate(mfd, int64(memBufSize)); err != nil {
			_ = unix.Close(mfd)
			mc.Close()
			return nil, fmt.Errorf("log: memfd: [%d] ftruncate: %w", i, err)
		}
		var data []byte
		data, err = unix.Mmap(mfd, 0, memBufSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			_ = unix.Close(mfd)
			mc.Close()
			return nil, fmt.Errorf("log: memfd: [%d] mmap: %w", i, err)
		}

		mc.bufs[i] = &mcbuf{
			fd:   os.NewFile(uintptr(mfd), fmt.Sprintf("mlogfile%d", i)),
			data: data,
		}
	}
	return mc, nil
}

// FDs returns the raw file descriptor integers for the two shared buffers
// backed by memfd. The receiver must use dup(2) fds to own these fds.
func (mc *Memconsole) FDs() (mfd1, mfd2 int) {
	return int(mc.bufs[0].fd.Fd()), int(mc.bufs[1].fd.Fd())
}

// Log implements log.Console.  It writes lvl-prefixed msg + '\n' into the
// active memfd buffer, flushing and flipping when the buffer is full.
func (mc *Memconsole) Log(lvl LogLevel, msg Logmsg) {
	if mc == nil || mc.closed.Load() {
		return
	}
	mc.write(lvl, msg)
}

// write serialises one log line into the next available fixed-width slot.
//
// Slot layout (memSlotSize = 800 bytes):
//
//	[0 : n]      level prefix (2 bytes) + message body (up to 797 bytes) + '\n'
//	[n : 800]    zero-filled tail
//
// The two-character level prefix (e.g. "W ") is prepended when absent.
// The message is hard-truncated to fit within one slot; no splitting occurs.
func (mc *Memconsole) write(lvl LogLevel, msg Logmsg) {
	mc.mu.Lock()

	if mc.closed.Load() {
		mc.mu.Unlock()
		return
	}

	lpfx := lvl.s()
	p := unsafe.StringData(msg)
	all := unsafe.Slice(p, len(msg))
	yank := len(all)
	i := 0

rollover:
	idx, logfd, start, end := -1, 0, 0, 0

	if mc.slotIdx >= memNumSlots { // active buffer full; attempt swap out
		other := mc.active ^ 1
		if !mc.draining[other].Load() {
			idx, logfd, start, end = mc.swapBuffersLocked()
			r := mc.reader
			go mc.consume(r, idx, logfd, start, end)
		} else { // the other buffer's consume is wip; cannot swap in
			mc.drops.Add(1)
			if overwriteOnFull { // ring-within-buffer: overwrite slots
				// TODO: write overwrite status to header?
				mc.slotIdx = 0
			} else { // drop write
				mc.mu.Unlock()
				return
			}
		}
	}

	b := mc.bufs[mc.active]

	for i < yank && mc.slotIdx < memNumSlots {
		// the slot at header + slotIdx * slotSize
		slot := b.data[memHdrSize+mc.slotIdx*memSlotSize : memHdrSize+(mc.slotIdx+1)*memSlotSize]

		raw := all[i:min(yank, i+memSlotSize)]
		n := 0
		if !bytes.HasPrefix(raw, []byte(lpfx)) {
			n = copy(slot, lpfx)
		}
		// reserve the last byte for newline
		m := copy(slot[n:memSlotSize-1], raw)
		slot[n+m] = '\n'
		// zero-fill the tail so the reader sees no stale data
		clear(slot[n+m+1:])

		i += m
		mc.slotIdx++
	}

	if i < yank {
		// mc.drops.Add(uint64((yank - i + memSlotSize - 1) / memSlotSize)) // count the number of dropped slots
		goto rollover
	}

	// start the lazy ticker while the buffer has unflushed slots but isn't full yet.
	needTicker := mc.slotIdx > 0 && mc.slotIdx < memNumSlots && !mc.closed.Load() && mc.ticking.CompareAndSwap(false, true)
	mc.mu.Unlock()

	if needTicker {
		go mc.ticker()
	}
}

// ticker is a one-shot timer goroutine started by the first-write after each
// buffer reset. It fires once after memFlushInterval and calls periodicFlush.
func (mc *Memconsole) ticker() {
	defer mc.ticking.Store(false)
	t := time.NewTimer(memFlushInterval)
	defer t.Stop()
	<-t.C
	mc.periodicFlush()
}

// periodicFlush drains the active buffer if it has content and no drain has
// been initiated recently. If the other buffer is currently being drained
// it restarts the ticker for another memFlushInterval rather than stacking
// concurrent Drain calls.
func (mc *Memconsole) periodicFlush() {
	mc.mu.Lock()

	if mc.closed.Load() || mc.slotIdx == 0 {
		mc.mu.Unlock()
		return // nothing to flush
	}
	if time.Since(mc.lastFlush) < memFlushInterval {
		mc.mu.Unlock()
		return // a buffer-full flush happened recently; skip
	}

	other := mc.active ^ 1
	if mc.draining[other].Load() {
		// the other buffer's Drain is still running; restart the ticker to retry
		if !mc.closed.Load() && mc.ticking.CompareAndSwap(false, true) {
			go mc.ticker()
		}
		mc.mu.Unlock()
		return
	}

	idx, logfd, start, end := mc.swapBuffersLocked()
	r := mc.reader
	mc.mu.Unlock()

	mc.consume(r, idx, logfd, start, end)
}

// swapBuffersLocked stamps the count header of the active buffer, sets its
// draining flag, flips active to the other buffer, and returns the Drain
// call parameters. Returns drainIdx=-1 when there is nothing to flush.
func (mc *Memconsole) swapBuffersLocked() (idx, fd, start, end int) {
	if mc.slotIdx == 0 {
		return -1, 0, 0, 0
	}
	mc.lastFlush = time.Now()

	idx = mc.active
	count := mc.slotIdx
	b := mc.bufs[idx]
	// prepare drain/consume
	b.setCountLocked(uint64(count))
	mc.draining[idx].Store(true)
	// swap active buffer out
	mc.active ^= 1
	mc.slotIdx = 0
	return idx, int(b.fd.Fd()), memHdrSize, memHdrSize + count*memSlotSize
}

// consume calls Drain for the prepared drain parameters, then resets the
// count header and clears the draining flag for that buffer. idx < 0 is a no-op.
func (mc *Memconsole) consume(r MemReader, idx, logfd, start, end int) {
	if idx < 0 {
		return
	}
	defer mc.draining[idx].Store(false)
	defer mc.bufs[idx].setCountLocked(0)

	r.Drain(logfd, start, end)
}

// Flush drains the currently active buffer and flips to the other buffer.
// It is a no-op when console has closed, or when there is no buffer to flush,
// or when the other buffer is still being drained concurrently.
func (mc *Memconsole) Flush() {
	mc.mu.Lock()
	if mc.closed.Load() || mc.slotIdx == 0 {
		mc.mu.Unlock()
		return
	}
	other := mc.active ^ 1
	if mc.draining[other].Load() {
		mc.mu.Unlock()
		return // other buffer still busy; skip rather than block
	}
	idx, logfd, start, end := mc.swapBuffersLocked()
	r := mc.reader
	mc.mu.Unlock()

	mc.consume(r, idx, logfd, start, end)
}

// Drops returns the cumulative number of buffer-full events where the
// active buffer could not be flipped (other buffer still draining) and
// the write either overwrote the oldest slot (overwriteOnFull=true) or
// was discarded (overwriteOnFull=false).
func (mc *Memconsole) Drops() uint64 { return mc.drops.Load() }

// SetReader installs r as the consumer of the Memconsole's shared-memory
// buffers.  Drain(fd, start, end) is called synchronously (but without
// mc.mu held) each time a buffer fills up or the periodic ticker fires;
// its return signals that the buffer is free for reuse.
func (mc *Memconsole) SetReader(r MemReader) {
	if mc == nil || r == nil {
		return
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.reader = r
}

// BufSize returns the byte size of each shared-memory region.  Pass this
// value to the external reader (e.g. via Console.LogMemFD) so it knows how
// large an mmap to perform.
func (mc *Memconsole) BufSize() int { return memBufSize }

// Close drains any pending data, waits for any concurrent Drain call to
// return, calls Close(), then unmaps the shared-memory regions and closes
// the memfds.
func (mc *Memconsole) Close() error {
	if mc == nil {
		return nil
	}

	if !mc.closed.CompareAndSwap(false, true) {
		return nil // already closed
	}

	// drain the active buffer. Any write() or periodicFlush()
	// already holding mu will complete first; subsequent ones see closed=true.
	if mc.slotIdx > 0 {
		other := mc.active ^ 1
		for mc.draining[other].Load() {
			runtime.Gosched() // wait for concurrent drain to finish so we can swap in the active buffer
		}
	}

	mc.mu.Lock()
	idx, logfd, start, end := mc.swapBuffersLocked()
	r := mc.reader
	mc.reader = nil
	mc.mu.Unlock()

	// called sync; Drain() is complete when it returns
	mc.consume(r, idx, logfd, start, end)

	if r != nil {
		r.OnClose()
	}
	for _, b := range mc.bufs {
		b.close()
	}
	return nil
}

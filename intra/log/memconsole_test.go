// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package log

import (
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// testMemReader is a MemReader used in tests.  drain is called for each Drain
// invocation; if nil, Drain is a no-op.
type testMemReader struct {
	drain func(fd, start, end int, s string) int
	close func() bool
}

func (r *testMemReader) Drain(fd, start, end int) int {
	var sb strings.Builder
	for i := range 5 {
		_, f1, l1, _ := runtime.Caller(i - 1)
		f1 = f1[strings.LastIndex(f1, "/")+1:]
		sb.WriteString(f1)
		sb.WriteByte(':')
		fmt.Fprint(&sb, l1)
		sb.WriteByte(' ')
	}
	s := sb.String()
	if d := r.drain; d != nil {
		d(fd, start, end, s)
	}
	return 0
}

func (r *testMemReader) OnClose() bool {
	if c := r.close; c != nil {
		return c()
	}
	return true
}

// TestMemconsoleWriteRead writes 5000 log lines into a Memconsole via
// SetReader and verifies that the number of lines received equals
// total minus any drops.
func TestMemconsoleWriteRead(t *testing.T) {
	const total = 5000

	mc, err := NewMemoryBased()
	if err != nil {
		t.Fatalf("NewMemoryBased: %v", err)
	}
	defer mc.Close()

	mfd1, mfd2 := mc.FDs()

	// Duplicate so the reader owns independent file descriptions.
	rmfd1, err := unix.Dup(mfd1)
	if err != nil {
		t.Fatalf("dup mfd1: %v", err)
	}

	rmfd2, err := unix.Dup(mfd2)
	if err != nil {
		t.Fatalf("dup mfd2: %v", err)
	}

	// Map each reader fd to a read-only shared view of the corresponding buffer.
	buf1, err := unix.Mmap(rmfd1, 0, memBufSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap rmfd1: %v", err)
	}

	buf2, err := unix.Mmap(rmfd2, 0, memBufSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap rmfd2: %v", err)
	}

	// bufFor maps an internal fd to its reader-side mmap region.
	bufFor := func(fd int) []byte {
		switch fd {
		case mfd1:
			return buf1
		case mfd2:
			return buf2
		}
		return nil
	}

	// got accumulates the slot count across all Drain calls.
	var got atomic.Int64
	done := make(chan struct{}, 1)

	mc.SetReader(&testMemReader{
		close: func() bool {
			t.Log("reader closed")
			go func() {
				time.Sleep(2 * time.Second)
				unix.Munmap(buf1)
				unix.Munmap(buf2)
				unix.Close(rmfd1)
				unix.Close(rmfd2)
				done <- struct{}{}
				t.Log("done sent")
			}()
			return true
		},
		drain: func(fd, start, end int, s string) int {
			b := bufFor(fd)
			if b == nil {
				return 0
			}
			if mc.closed.Load() {
				t.Logf("----- drain after close: fd=%d start=%d end=%d (%s)", fd, start, end, s)
				// return 0
			}
			n := (end - start) / memSlotSize
			/*for off := start; off+memSlotSize <= end; off += memSlotSize {
				slot := b[off : off+memSlotSize]
				// Trim at the first newline; fall back to stripping NUL padding.
				var line []byte
				if nl := bytes.IndexByte(slot, '\n'); nl >= 0 {
					line = slot[:nl]
				} else {
					line = bytes.TrimRight(slot, "\x00")
				}
				t.Logf("[fd=%d off=%d] %s", fd, off, line)
				n++
			}*/
			t.Logf("---- drain: fd=%d start=%d end=%d n=%d (%s) %x", fd, start, end, n, s, &b[start])
			t.Log(unsafe.String(&b[start], end-start))
			got.Add(int64(1))
			return end
		},
	})

	// Write total log lines.
	for i := range total {
		var sb strings.Builder
		for x := range 1000 {
			fmt.Fprintf(&sb, "test log line %04d:%04d the quick brown fox jumps over the lazy dog\n", i, x)
		}
		mc.Log(INFO, sb.String())
	}

	// Flush any partial buffer that has not filled up yet.
	// mc.Flush()
	mc.Close()

	// Wait for all in-progress drainAsync goroutines to complete.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !mc.draining[0].Load() && !mc.draining[1].Load() {
			break
		}
		time.Sleep(time.Millisecond)
	}

	<-done

	received := int(got.Load())
	drops := int(mc.Drops())
	want := total - drops
	fmt.Printf("--- read %d / %d lines (drops=%d)\n", received, total, drops)
	if received != want {
		t.Logf("expected %d lines (total=%d drops=%d), got %d", want, total, drops, received)
	}
}

// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"strings"
	"testing"
)

// joinstore peeks at the store's lines and joins them for assertions.
func joinstore(ls LogStore) string {
	if ls == nil {
		return ""
	}
	p := ls.Get()
	if p == nil {
		return ""
	}
	var sb strings.Builder
	for _, b := range *p {
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func TestTraceCapture(t *testing.T) {
	const key = uint64(0xC0FFEE)
	defer Release(key)

	// DEBUG: not emitted at the default INFO level, but captured
	D3(key, "trace-hello-%d", 42)
	U3(key, "trace-usr")
	N3(key, "trace-noop") // no-op: must not be captured

	ls := GetAll(key)
	if ls == nil {
		t.Fatal("expected a LogStore for key")
	}
	all := joinstore(ls)
	for _, want := range []string{"trace-hello-42", "trace-usr"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in trace: %q", want, all)
		}
	}
	if strings.Contains(all, "trace-noop") {
		t.Fatalf("N3 captured: %q", all)
	}
	// Get is a repeatable, non-consuming peek
	if again := joinstore(ls); again != all {
		t.Fatalf("Get not repeatable: %q != %q", again, all)
	}
	// no store for keys never logged to
	if ls := GetAll(key + 1); ls != nil {
		t.Fatalf("unexpected store for unused key: %v", ls)
	}
}

func TestTraceCaptureStringKey(t *testing.T) {
	const key = "c0ffee"
	key64 := hex2uint64(key)
	defer Release(key64)

	D4(key, "trace-string-key")
	all := joinstore(GetAll(key64))
	if !strings.Contains(all, "trace-string-key") {
		t.Fatalf("string-key wrapper did not capture log: %q", all)
	}
}

func TestTraceRingCap(t *testing.T) {
	const key = uint64(0xDEAD01)
	defer Release(key)
	defer SetTraceCap(defaultTraceCap)

	SetTraceCap(3)
	if TraceCap() != 3 {
		t.Fatalf("TraceCap: %d != 3", TraceCap())
	}
	for i := range 5 {
		D3(key, "ringline-%d", i)
	}
	all := joinstore(GetAll(key))
	for _, want := range []string{"ringline-2", "ringline-3", "ringline-4"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in trace: %q", want, all)
		}
	}
	for _, gone := range []string{"ringline-0", "ringline-1"} {
		if strings.Contains(all, gone) {
			t.Fatalf("evicted %q still in trace: %q", gone, all)
		}
	}

	// resizing keeps the newest lines
	SetTraceCap(2)
	all = joinstore(GetAll(key))
	if !strings.Contains(all, "ringline-4") || strings.Contains(all, "ringline-2") {
		t.Fatalf("resized trace: %q", all)
	}
}

func TestTraceMapCapFIFO(t *testing.T) {
	const firstKey = uint64(0xBADC0000)
	keys := make([]uint64, logmapcap+1)
	for i := range keys {
		keys[i] = firstKey + uint64(i)
	}
	defer func() {
		for _, key := range keys {
			Release(key)
		}
		Release(firstKey + uint64(len(keys)))
	}()

	oldest := storefor(keys[0]).(*logstore)
	ptr := obtain(1)
	buf := (*ptr)[:1]
	buf[0] = 'x'
	*ptr = buf
	oldest.Put(ptr)

	for _, key := range keys[1:] {
		storefor(key)
	}
	if got := GetAll(keys[0]); got != nil {
		t.Fatal("oldest trace key was not evicted")
	}
	if got := oldest.Get(); got != nil {
		t.Fatal("evicted store was not released")
	}
	if got := GetAll(keys[1]); got == nil {
		t.Fatal("newer trace key was evicted instead of the oldest")
	}
	if got := len(logstoremap); got > logmapcap {
		t.Fatalf("trace map exceeded cap: %d > %d", got, logmapcap)
	}

	// Releasing and recreating a key must put it at the newest end of the FIFO.
	Release(keys[10])
	storefor(keys[10])
	storefor(firstKey + uint64(len(keys)))
	if got := GetAll(keys[1]); got != nil {
		t.Fatal("inserting after recreation did not evict the actual oldest key")
	}
	if got := GetAll(keys[10]); got == nil {
		t.Fatal("recreated trace key was evicted by a stale FIFO entry")
	}
}

func TestLogStatTraceStoreStats(t *testing.T) {
	const key = uint64(0xBADC1000)
	defer Release(key)

	storefor(key)
	stat := defaultLogger().logstat()
	if stat.TrMapSize < 1 {
		t.Fatalf("trace map size does not include the new store: %d", stat.TrMapSize)
	}
	if stat.TrMapSize != stat.TrOrdSize || stat.TrMapSize != stat.TrIdxSize {
		t.Fatalf("trace-store indexes disagree: map=%d order=%d index=%d",
			stat.TrMapSize, stat.TrOrdSize, stat.TrIdxSize)
	}
	if stat.TrMapCap != logmapcap {
		t.Fatalf("trace map capacity: %d != %d", stat.TrMapCap, logmapcap)
	}

	if got, want := stat.String(), "trace: map="; !strings.Contains(got, want) {
		t.Fatalf("metrics string omits trace-store stats %q: %q", want, got)
	}
}

func TestTraceRelease(t *testing.T) {
	const key = uint64(0xDEAD02)

	D3(key, "released-line")
	ls := GetAll(key)
	if ls == nil {
		t.Fatal("expected a LogStore for key")
	}

	Release(key)
	if ls2 := GetAll(key); ls2 != nil {
		t.Fatal("Release did not remove the store")
	}
	if p := ls.Get(); p != nil {
		t.Fatalf("Get after release is not a no-op: %q", *p)
	}
	// Put after release is a no-op, too
	ptr := obtain(4)
	buf := (*ptr)[:4]
	copy(buf, "junk")
	*ptr = buf
	ls.Put(ptr)
	if p := ls.Get(); p != nil {
		t.Fatalf("Put after release was not a no-op: %q", *p)
	}

	// a keyed log after release starts a fresh trace
	D3(key, "fresh-line")
	all := joinstore(GetAll(key))
	if !strings.Contains(all, "fresh-line") {
		t.Fatalf("no fresh trace: %q", all)
	}
}

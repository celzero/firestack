// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"io"
	golog "log"
	"math/rand/v2"
	"runtime"
	"testing"
	"unsafe"
)

var sinkPC uintptr
var sinkFile string

func BenchmarkSpamID(b *testing.B) {
	msg := "abcdefghijk1234567890" // >12 chars; only first 12 used
	raw := unsafe.StringData(msg)

	b.Run("fhash12", func(b *testing.B) {
		var h uint64
		for b.Loop() {
			h = fhash(unsafe.Slice(raw, 12))
		}
		sinkPC = uintptr(h)
	})

	b.Run("Caller", func(b *testing.B) {
		for b.Loop() {
			pc, file, _, _ := runtime.Caller(0)
			sinkPC = pc
			sinkFile = file
		}
	})
}

// benchmsg returns a pseudo-random string of length in [1, 2048].
func benchmsg(rng *rand.Rand) string {
	n := 1 + rng.IntN(2048)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + rng.IntN(26))
	}
	return unsafe.String(&b[0], n)
}

func BenchmarkLogCall(b *testing.B) {
	// log levels to benchmark, mapped to their logger methods
	type levelTest struct {
		name string
		call func(l *simpleLogger, at int, msg string)
	}
	levels := []levelTest{
		{"VV", func(l *simpleLogger, at int, msg string) { l.VeryVerbosef(at, msg) }},
		{"V", func(l *simpleLogger, at int, msg string) { l.Verbosef(at, msg) }},
		{"D", func(l *simpleLogger, at int, msg string) { l.Debugf(at, msg) }},
		{"I", func(l *simpleLogger, at int, msg string) { l.Infof(at, msg) }},
		{"W", func(l *simpleLogger, at int, msg string) { l.Warnf(at, msg) }},
		{"E", func(l *simpleLogger, at int, msg string) { l.Errorf(at, msg) }},
	}

	// callerdepth values to benchmark
	depths := []uint8{0, 5, 9}

	oncemsg := benchmsg(rand.New(rand.NewChaCha8([32]byte{42})))

	for _, depth := range depths {
		for _, lt := range levels {
			name := lt.name + "/depth" + string(rune('0'+depth))
			b.Run(name, func(b *testing.B) {
				l := NewLogger("bench")
				l.SetLevel(VVERBOSE)
				l.SetCallerDepth(depth)
				// suppress stdout/stderr I/O so benchmark measures CPU, not write(2)
				l.o = golog.New(io.Discard, "", 0)
				l.e = golog.New(io.Discard, "", 0)

				// rng := rand.New(rand.NewChaCha8([32]byte{42}))

				for b.Loop() {
					lt.call(l, callerat, oncemsg)
				}
			})
		}
	}
}

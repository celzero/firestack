// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//	MIT License
//
//	Copyright (c) 2018 eycorsican
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.

package log

import (
	"context"
	"fmt"
	"hash/fnv"
	golog "log"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

type Logger interface {
	SetLevel(level LogLevel)
	SetConsoleLevel(level LogLevel)
	SetConsole(c Console)
	Usr(msg string)
	Printf(msg string, args ...any)
	VeryVerbosef(at int, msg string, args ...any)
	Verbosef(at int, msg string, args ...any)
	Debugf(at int, msg string, args ...any)
	Piif(at int, msg string, args ...any)
	Infof(at int, msg string, args ...any)
	Warnf(at int, msg string, args ...any)
	Errorf(at int, msg string, args ...any)
	Fatalf(at int, msg string, args ...any)
	Trace(c bool, t string)
	Stack(at int, msg string, scratch []byte)
}

// based on github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/simple/logger.go
type simpleLogger struct {
	tag string

	level LogLevel // golog (internal log) level

	c      atom[Console]
	clevel LogLevel      // may be different from level
	cmsgC  chan *conMsg  // never closed
	cskips atomic.Uint32 // number of dropped console msgs

	stmu    sync.Mutex        // guards stcount
	stcount map[uint64]uint32 // stack trace counter for identical traces

	o *golog.Logger
	e *golog.Logger
	q *ring[string] // todo: use []byte instead of string for gc?

	clock
	skips
}

type atom[T any] atomic.Value

func (a *atom[T]) get() (zz T) {
	if a == nil {
		return
	}
	aa := (*atomic.Value)(a)
	if t, ok := aa.Load().(T); ok {
		return t
	}
	return zz
}

func (a *atom[T]) set(t T) (ok bool) {
	if a == nil {
		return
	}
	if isNil(t) {
		zz := &atom[T]{}
		*a = *zz
		return
	}
	old := a.get()
	if !typeEq(old, t) {
		r := &atom[T]{}
		*a = *r
	}
	aa := (*atomic.Value)(a)
	return aa.CompareAndSwap(old, t)
}

const pcbuckets = 512

// a clock-like spam rate limiter
// maps level+pc to its age in ticks
type clock struct {
	l2 [NONE + 1][pcbuckets]uatom[uint8] // level+pc clock
	l1 [NONE + 1]uatom[uint8]            // level clock
}

// number of per-level dropped (spammy) logs
type skips [NONE + 1]atomic.Uint32

type uatom[T uint8 | uint16] atomic.Uint32

func (a *uatom[T]) v() T {
	aa := (*atomic.Uint32)(a)
	return T(aa.Load())
}

func (a *uatom[T]) inc() T {
	aa := (*atomic.Uint32)(a)
	return T(aa.Add(1))
}

func (a *uatom[T]) cas(old, new T) bool {
	aa := (*atomic.Uint32)(a)
	return aa.CompareAndSwap(uint32(old), uint32(new))
}

var _ Logger = (*simpleLogger)(nil)

type LogLevel uint32

const (
	VVERBOSE   LogLevel = iota // VVERBOSE is the most verbose log level.
	VERBOSE                    // VERBOSE is the verbose log level.
	DEBUG                      // DEBUG is the debug log level.
	INFO                       // INFO is the informational log level.
	WARN                       // WARN is the warning log level.
	ERROR                      // ERROR is the error log level.
	STACKTRACE                 // STACKTRACE is the stack trace log level.
	USR                        // USR is interactive log (e.g. as user prompt).
	NONE                       // NONE no-ops the logger.
)

func (l LogLevel) s() string {
	switch l {
	case VVERBOSE:
		return "Y "
	case VERBOSE:
		return "V "
	case DEBUG:
		return "D "
	case INFO:
		return "I "
	case WARN:
		return "W "
	case ERROR:
		return "E "
	case STACKTRACE:
		return "F "
	case USR:
		return "U "
	case NONE:
		return "  "
	default:
		return "? "
	}
}

const consoleStacktraceSep = "\n<===>\n"

const defaultLevel = INFO
const defaultClevel = STACKTRACE

var _ Logger = (*simpleLogger)(nil)

// runtime crashes "E Go ..." are sent to logd / /dev/log from here:
// github.com/golang/go/blob/3fd729b2a1/src/runtime/write_err_android.go#L13
// github.com/golang/mobile/blob/fa72addaaa/internal/mobileinit/mobileinit_android.go#L52
// const logcatLineSize = 1024

const spamConsole = false // send spammy logs to console
const logPiif = false     // enable sensitive logs

// qSize is the number of recent log msgs to keep in the ring buffer.
const qSize = 512

// minQSize is the minimum most number of recent log msgs to actually log.
// by default, all msgs in the qSize'd ring buffer are logged.
const minQSize = 16

// consoleChSize is the size of the console channel.
const consoleChSize = 512

// minBytesForFullStacktrace is the size needed for a full stacktrace.
const minBytesForFullStacktrace = 16 << 10 // 16KB

// similarTraceThreshold is the no. of similar stacktraces to report before suppressing.
const similarTraceThreshold = 8

// similarUsrMsgThreshold is the no. of similar user msgs to report before suppressing.
const similarUsrMsgThreshold = 3

// charsPerLine is max no. of characters per log line.
const charsPerLine = 300

// spamMsgThreshold is the min. no. of spammy msgs to report.
var spammsgThreshold = [NONE + 1]uint32{
	VVERBOSE:   256 >> 1, // 128
	VERBOSE:    256 >> 2, // 64
	DEBUG:      256 >> 3, // 32
	INFO:       256 >> 4, // 16
	WARN:       256 >> 5, // 8
	ERROR:      256 >> 6, // 4
	STACKTRACE: 256 >> 7, // 2
	USR:        256 >> 8, // 1
	NONE:       256 >> 9, // 0
}

const callerunknown = "???"

const defaultFlags = 0 // no flags

func defaultLogger() *simpleLogger {
	l := &simpleLogger{
		level:   defaultLevel,
		clevel:  defaultClevel,
		cmsgC:   make(chan *conMsg, consoleChSize),
		stcount: make(map[uint64]uint32),
		// gomobile pipes stderr & stdout to logcat
		// github.com/golang/mobile/blob/fa72addaaa/internal/mobileinit/mobileinit_android.go#L74-L92
		e: golog.New(os.Stderr, "", defaultFlags),
		o: golog.New(os.Stdout, "", defaultFlags),
		q: newRing[string](context.TODO(), qSize),
	}
	go l.consoleDispatcher()
	return l
}

// NewLogger creates a new Glogger with the given tag.
func NewLogger(tag string) *simpleLogger {
	l := defaultLogger()
	if len(tag) <= 0 { // if tag is empty, leave it as is
		return l
	}
	if !strings.HasSuffix(tag, "/") {
		tag += "/ " // does not end with a /, add a / + space
	} else if !strings.HasSuffix(tag, " ") {
		tag += " " // does not end with a space, add space
	}
	l.tag = tag
	return l
}

// SetLevel sets the log level.
func (l *simpleLogger) SetLevel(n LogLevel) {
	l.level = n
}

// SetLevel sets the log level.
func (l *simpleLogger) SetConsoleLevel(n LogLevel) {
	l.clearStCounts()
	l.clevel = n
}

// SetConsole sets the external log console.
func (l *simpleLogger) SetConsole(c Console) {
	l.clearStCounts()

	l.c.set(c) // c may point to nil impl
}

func (l *simpleLogger) clearStCounts() {
	l.stmu.Lock()
	defer l.stmu.Unlock()
	clear(l.stcount)
}

// xor fold fnv to 48 bits: www.isthe.com/chongo/tech/comp/fnv
func fhash(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}

func (l *simpleLogger) incrStCount(id string) (c uint32) {
	l.stmu.Lock()
	defer l.stmu.Unlock()

	if len(id) > 500 {
		id = id[:500]
	}
	loc := fhash([]byte(id))
	c = l.stcount[loc]
	l.stcount[loc]++
	return c
}

// consoleDispatcher sends msgs from l.msgC to external log console.
// It may drop logs on high load (50% for conNorm, 80% for conErr).
// Must be called once from a goroutine.
func (l *simpleLogger) consoleDispatcher() {
	for m := range l.cmsgC {
		if m == nil || len(m.m) <= 0 { // no msg
			continue
		}
		load := (len(l.cmsgC) / cap(l.cmsgC) * 100) // load percentage
		if c := l.c.get(); c != nil && !isNil(c) {  // look for l.c on every msg
			switch m.t {
			case NONE:
				// drop
			case VVERBOSE, VERBOSE, DEBUG, INFO:
				if load < 50 {
					c.Log(m.t, m.m)
					continue
				} // drop
			case WARN, ERROR:
				if load < 5 {
					if d := l.cskips.Swap(0); d > 0 {
						c.Log(WARN, Logmsg(l.msgstr(WARN, "backpressure... dropped %d msgs", d)))
					}
				}
				if load < 80 {
					c.Log(m.t, m.m)
					continue
				} // drop
			case STACKTRACE:
				c.Log(m.t, m.m)
				continue
			case USR:
				c.Log(m.t, m.m)
				continue
			}
		} // dropped
		l.cskips.Add(1)
	}
}

// consoleQueue sends msg m to l.msgC, dropping if full.
func (l *simpleLogger) consoleQueue(m *conMsg) {
	select {
	case l.cmsgC <- m:
	default: // drop
	}
}

func (l *simpleLogger) Usr(msg string) {
	if l.level <= USR {
		if count := l.incrStCount(msg); count > similarUsrMsgThreshold {
			return
		}
		l.consoleQueue(&conMsg{Logmsg(msg), USR})
	}
}

// Printf exists to satisfy rnet/http's Logger interface
func (l *simpleLogger) Printf(msg string, args ...any) {
	l.Debugf(callerat, msg, args...)
}

func (l *simpleLogger) VeryVerbosef(at int, msg string, args ...any) {
	l.writelog(VVERBOSE, at+nextframe, msg, args...)
}

func (l *simpleLogger) Verbosef(at int, msg string, args ...any) {
	l.writelog(VERBOSE, at+nextframe, msg, args...)
}

func (l *simpleLogger) Debugf(at int, msg string, args ...any) {
	l.writelog(DEBUG, at+nextframe, msg, args...)
}

func (l *simpleLogger) Piif(at int, msg string, args ...any) {
	if logPiif {
		l.writelog(INFO, at+nextframe, msg, args...)
	}
}

func (l *simpleLogger) Infof(at int, msg string, args ...any) {
	l.writelog(INFO, at+nextframe, msg, args...)
}

func (l *simpleLogger) Warnf(at int, msg string, args ...any) {
	l.writelog(WARN, at+nextframe, msg, args...)
}

func (l *simpleLogger) Errorf(at int, msg string, args ...any) {
	l.writelog(ERROR, at+nextframe, msg, args...)
}

func (l *simpleLogger) Fatalf(at int, msg string, args ...any) {
	// todo: log to console?
	l.err(at+nextframe, l.msgstr(STACKTRACE, msg, args...))
	os.Exit(1)
}

// emitStack sends stacktrace to console or log.
// Empty msgs are ignored.
func (l *simpleLogger) emitStack(at int, msgs ...string) {
	sendtoconsole := at <= callerat
	if !sendtoconsole {
		for _, msg := range msgs {
			if len(msg) <= 0 {
				continue
			}
			l.err(at+nextframe, msg)
		}
	} else if c := l.c.get(); c != nil && !isNil(c) {
		// buffer copy :( but the msgs need to be sent as a single unit
		// for kotlin-land to process them as being from the same panic.
		msg := strings.Join(msgs, consoleStacktraceSep)
		if len(msg) <= 0 {
			return
		}
		// c.Stack() on the same go routine, since
		// the caller (ex: core.Recover) may exit
		// immediately once simpleLogger.Stack() returns
		c.Log(STACKTRACE, Logmsg(msg))
	} else {
		// msg, which is unsafely type-coerced from []byte,
		// is pooled; but the caller owns []byte and so it
		// cannot be used asynchronously (ex: over channels).
		// l.toConsole(&conMsg{msg, STACKTRACE})
		l.cskips.Add(1)
	}
}

func (l *simpleLogger) Trace(c bool, t string) {
	if len(t) <= 0 {
		return
	}
	at := callerat // emits to console
	if !c {
		at += nextframe // emits to stdout
	}
	l.emitStack(at, t)
}

func (l *simpleLogger) Stack(at int, msg string, scratch []byte) {
	at += nextframe
	if len(l.tag) > 0 {
		msg = l.tag + msg
	}

	if l.level > STACKTRACE {
		l.emitStack(at, msg, "stacktrace disabled")
		return
	} else if len(scratch) <= 0 {
		l.emitStack(at, msg, "stacktrace no scratch")
		return
	}

	count := l.incrStCount(msg)
	msg = msg + fmt.Sprintf(" (#%d)", count)
	if count > similarTraceThreshold {
		l.emitStack(at, msg, "stacktrace suppressed")
		return
	}

	// full stacktrace iff large enough scratch
	full := len(scratch) > minBytesForFullStacktrace // 16KB
	n := runtime.Stack(scratch, full)

	if n == len(scratch) {
		msg += "[trunc]"
	}

	prev := l.queued(full)

	// byt2str accepted proposal: github.com/golang/go/issues/19367
	// previous discussion: github.com/golang/go/issues/25484
	trace := unsafe.String(&scratch[0], n)
	msgcat := strings.Join([]string{msg, trace, prev}, consoleStacktraceSep)
	l.emitStack(at, msgcat)
}

func (l *simpleLogger) queued(all bool) (appendix string) {
	maxlines := qSize
	if !all {
		maxlines = minQSize
	}
	i := 0
	// todo: interned strings github.com/golang/go/issues/62483
	lines := make([]string, maxlines)
	for recent := range l.q.Iter() {
		lines[i] = recent
		i++
		if i >= len(lines) {
			break
		}
	}
	if i > 0 {
		appendix = strings.Join(lines[:i], "\n")
	}
	return
}

func (l *simpleLogger) msgstr(lvl LogLevel, f string, args ...any) (msg string) {
	level := lvl.s()

	if len(f) <= 0 {
		return level + l.tag + "<empty>"
	}
	if len(args) <= 0 {
		return level + l.tag + f
	}
	msg = fmt.Sprintf(f, args...)
	if len(msg) <= charsPerLine { // excl tag+level
		return level + l.tag + msg
	}

	var s strings.Builder
	for i := 0; i < len(msg); i += charsPerLine {
		if i > 0 {
			s.WriteByte('\n')
		}
		s.WriteString(level)
		if len(l.tag) > 0 {
			s.WriteString(l.tag)
		}
		end := min(i+charsPerLine, len(msg))
		s.WriteString(msg[i:end])
	}
	return s.String()
}

// out logs to stdout and pushes msg into ring buffer.
// ref: github.com/golang/mobile/blob/c713f31d/internal/mobileinit/mobileinit_android.go#L51
func (l *simpleLogger) out(msg string) {
	_ = l.o.Output(0 /*not used*/, msg) // may error
	l.q.Push(msg)
}

// err logs to stderr and pushes msg into ring buffer.
func (l *simpleLogger) err(at int, msg string) {
	_, file := caller(at + nextframe)
	msg = file + msg
	_ = l.e.Output(0 /*unused*/, msg) // may error
	l.q.Push(msg)
}

func caller(at int) (pc uintptr, who string) {
	return caller2(at+nextframe, ":", ": ")
}

func caller2(at int, sep1, sep2 string) (pc uintptr, who string) {
	pc, file, line, _ := runtime.Caller(at)
	if len(file) <= 0 {
		file = callerunknown
	} else {
		file = shortfile(file) + sep1 + fmt.Sprint(line) + sep2
	}
	return pc, file
}

// go.dev/play/p/h9Woqcp0Xz0
func callers(at, until int, sep1 string) (pcs []uintptr, files []string, skipped int) {
	if until <= 0 {
		return []uintptr{0}, []string{callerunknown}, 0
	} else if until == 1 {
		pc, who := caller2(at+nextframe, sep1, "")
		return []uintptr{pc}, []string{who}, 0
	}

	rpc := make([]uintptr, until)
	n := runtime.Callers(at+nextframe, rpc)
	if n < 1 {
		return []uintptr{0}, []string{callerunknown}, until
	}

	pcs = make([]uintptr, 0, until)
	files = make([]string, 0, until)
	frames := runtime.CallersFrames(rpc)
	for i := range until {
		frame, more := frames.Next()
		pc := frame.PC // may be 0
		file := frame.File
		line := frame.Line
		if len(file) <= 0 { // more is false when file is empty
			file = callerunknown
		} else {
			file = shortfile(file) + sep1 + fmt.Sprint(line)
		}
		pcs = append(pcs, pc)
		files = append(files, file)
		if !more || file == callerunknown {
			break
		}
		skipped = until - i
	}
	return
}

func tracecaller(s string) bool {
	if len(s) <= 0 || s == callerunknown {
		return false
	}
	// ex: asm_arm64.s:1223>async.go:49>async.go:121>proxy.go:789
	if strings.Contains(s, "asm_") && strings.Contains(s, ".s") {
		return false // asm files are not useful
	}
	return true
}

func shortfile(file string) string {
	if i := strings.LastIndexByte(file, '/'); i >= 0 {
		file = file[i+1:]
	}
	return file
}

func (l *simpleLogger) writelog(lvl LogLevel, at int, msg string, args ...any) {
	ll := l.level <= lvl
	cc := l.clevel <= lvl

	pc, file1 := caller(at + nextframe)
	trace := ""

	isspam := l.spammy(lvl, pc)
	if isspam {
		l.skips[lvl].Add(1)
	}

	if n := l.skips[lvl].Load(); n > spammsgThreshold[lvl] {
		swapped := l.skips[lvl].CompareAndSwap(n, 0)
		if swapped && (cc || ll) {
			spammsg := l.msgstr(lvl, file1+"spammy... %d msgs; dropped? %t", n, !spamConsole)
			if ll {
				l.out(spammsg)
			}
			// print spammsg only if spamming is not allowed
			if cc && !spamConsole {
				l.consoleQueue(&conMsg{Logmsg(spammsg), lvl})
			}
		}
	}

	if ll || cc {
		_, x, _ := callers(at+nextframe, 7, ":")
		switch lvl {
		case USR, STACKTRACE, NONE: // no-op
		case VVERBOSE:
			if len(x) >= 7 && tracecaller(x[6]) {
				trace += x[6] + ">"
			}
			fallthrough
		case VERBOSE:
			if len(x) >= 6 && tracecaller(x[5]) {
				trace += x[5] + ">"
			}
			fallthrough
		case DEBUG:
			if len(x) >= 5 && tracecaller(x[4]) {
				trace += x[4] + ">"
			}
			fallthrough
		case ERROR:
			if len(x) >= 4 && tracecaller(x[3]) {
				trace += x[3] + ">"
			}
			fallthrough
		case WARN:
			if len(x) >= 3 && tracecaller(x[2]) {
				trace += x[2] + ">"
			}
			fallthrough
		case INFO:
			if len(x) >= 2 && tracecaller(x[1]) {
				trace += x[1] + ">"
			}
			fallthrough
		default:
			if tracecaller(file1) { // same as x[0]
				trace += file1
			}
			if len(trace) > 0 {
				trace += ": " // end-of-trace marker
			}
		}
		msg = l.msgstr(lvl, trace+msg, args...)
		if ll {
			// go's internal logger grabs mutex before every write
			l.out(msg)
		}
		if cc && (!isspam || spamConsole) {
			l.consoleQueue(&conMsg{Logmsg(msg), lvl})
		}
	}
}

// go.dev/play/p/6CkoACJ1bYz
func (l *simpleLogger) spammy(lvl LogLevel, pc uintptr) (y bool) {
	resyncAttempts := 0

top:
	t := (l.clock.l1[lvl]).inc() // tick the level clock

	if pc == 0 {
		return false
	}
	// won't work:  l2 := l.clock.l2[lvl]
	// go.dev/play/p/QgqEdE7KIAZ
	bkt := pc % pcbuckets

	defer func() {
		if !y { // age bkt when not spammy
			(l.clock.l2[lvl][bkt]).inc()
		}
	}()

	v := (l.clock.l2[lvl][bkt]).v()

	// reset if pc clock (l2) out ticks level clock (l1);
	// ie, t has probably overflowed to next generation
	// and in that generation, bkt has not yet born.
	// and so reset bkt to 0 or any value < t
	if v > t {
		resyncd := (l.clock.l2[lvl][bkt]).cas(t, 0) // set to t/2?
		if resyncd {
			return false // not spammy
		} // else: someone else won the race
		resyncAttempts++
		if resyncAttempts <= 3 {
			goto top
		} // else: so many calls that atomic updates won't go through
		// assume spammy as that's most likely to be the case
		return false
	}

	tt := uint16(t) // tolerable ticks
	if t < 256>>4 { // for upto 16 ticks
		tt = tt * 70 / 100 // allow upto 70% of ticks
	} else if t < 256>>3 { // for upto 32 ticks
		tt = tt * 60 / 100 // allow upto 60% of ticks
	} else if t < 256>>2 { // for upto 64 ticks
		tt = tt * 50 / 100 // allow upto 50% of ticks
	} else if t < 256>>1 { // for upto 128 ticks
		tt = tt * 40 / 100 // allow upto 40% of ticks
	} else { // for upto 256 ticks
		tt = tt * 30 / 100 // allow upto 30% of ticks
	}
	return uint16(v) > tt
}

// Cannot import pkg core here.
// from: intra/core/typ.go:isNil
func isNil(x any) bool {
	// from: stackoverflow.com/a/76595928
	if x == nil {
		return true
	}
	v := reflect.ValueOf(x)
	k := v.Kind()
	switch k {
	case reflect.Pointer, reflect.UnsafePointer, reflect.Interface, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// from: intra/core/typ.go:typeEq
func typeEq(a, b any) bool {
	if isNil(a) {
		return false
	} else if isNil(b) {
		return false
	}
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

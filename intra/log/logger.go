// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//	  MIT License
//
//	  Copyright (c) 2018 eycorsican
//
//	  Permission is hereby granted, free of charge, to any person obtaining a copy
//	  of this software and associated documentation files (the "Software"), to deal
//	  in the Software without restriction, including without limitation the rights
//	  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	  copies of the Software, and to permit persons to whom the Software is
//	  furnished to do so, subject to the following conditions:
//
//	  The above copyright notice and this permission notice shall be included in all
//	  copies or substantial portions of the Software.
//
//	  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	  SOFTWARE.

package log

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	golog "log"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

// originally: github.com/eycorsican/go-tun2socks/blob/301549c43/common/log/simple/logger.go

type Logger interface {
	SetLevel(level LogLevel)
	SetConsoleLevel(level LogLevel)
	SetConsole(c Console)
	SetCallerDepth(d uint8)
	ConsoleReady(ctx context.Context)
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
	Hist(w io.Writer) int
	Metrics() *LogStat
}

type simpleLogger struct {
	tag string

	level LogLevel // golog (internal log) level

	callerdepth uint8 // total frames to dig per log call

	c      atom[Console]
	clevel LogLevel      // may be different from level
	cmsgC  chan *conMsg  // never closed
	cskips atomic.Uint32 // number of dropped console msgs

	stmu    sync.Mutex        // guards stcount
	stcount map[uint64]uint32 // stack trace counter for identical traces

	o *golog.Logger
	e *golog.Logger
	x *xlog          // may be used instead of golog o/e
	q *ring[*[]byte] // ring buffer of pooled []byte slabs

	clock
	skips

	// per-level counters (updated atomically in writelog)
	ncount [NONE + 1]atomic.Uint64 // total messages logged
	nbytes [NONE + 1]atomic.Uint64 // total bytes formatted
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
		aa := (*atomic.Value)(a)
		aa.Store(t)
		return true
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

const (
	maxCallerDepth = 9
	minCallerDepth = 0
)

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
const consoleChSize = 2048

// minBytesForFullStacktrace is the size needed for a full stacktrace.
const minBytesForFullStacktrace = 16 << 10 // 16KB

// similarTraceThreshold is the no. of similar stacktraces to report before suppressing.
const similarTraceThreshold = 8

// similarUsrMsgThreshold is the no. of similar user msgs to report before suppressing.
const similarUsrMsgThreshold = 3

// charsPerLine is max no. of characters per log line.
// less than 1024: github.com/golang/mobile/blob/2553ed8ce2/internal/mobileinit/mobileinit_android.go#L52
const charsPerLine = 800

// prependTrace if true, prepends trace information to log msg; appends, otherwise.
const prependTrace = false

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

const fileunknown = "?f?"
const callerunknown = "?c?"

const defaultFlags = 0 // no flags

var Debug = false
var Verbose = false

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
		x: &xlog{}, // pipes output to logcat on Android, to fmt.Print otherwise
		q: newRing(context.TODO(), qSize, recycle),
	}
	if runtime.GOOS == "android" {
		golog.SetOutput(l.x)
	}
	return l
}

// NewLogger creates a new Logger with the given tag.
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

	Debug = (l.level <= DEBUG || l.clevel <= DEBUG)
	Verbose = Debug && (l.level <= VERBOSE || l.clevel <= VERBOSE)
}

// SetLevel sets the log level.
func (l *simpleLogger) SetConsoleLevel(n LogLevel) {
	l.clearStCounts()
	l.clevel = n
	Debug = (l.level <= DEBUG || l.clevel <= DEBUG)
	Verbose = Debug && (l.level <= VERBOSE || l.clevel <= VERBOSE)
}

// SetCallerDepth sets total frames to unearth for every log fn call.
func (l *simpleLogger) SetCallerDepth(d uint8) {
	l.callerdepth = min(max(d, minCallerDepth), maxCallerDepth)
}

// SetConsole sets the external log console.
func (l *simpleLogger) SetConsole(c Console) {
	l.clearStCounts()

	l.c.set(c) // c may point to nil impl
}

func (l *simpleLogger) ConsoleReady(ctx context.Context) {
	go l.consoleDispatcher(ctx)
	// TODO: close l.msgC when ctx is done
	// TODO: wireup ctx to l.q
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
	loc := fhash(unsafe.Slice(unsafe.StringData(id), len(id)))
	c = l.stcount[loc]
	l.stcount[loc]++
	return c
}

// consoleDispatcher sends msgs from l.msgC to external log console.
// It may drop logs on high load (50% for conNorm, 80% for conErr).
// Must be called once from a goroutine.
func (l *simpleLogger) consoleDispatcher(ctx context.Context) {
	for m := range l.cmsgC {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if m == nil || len(m.m) <= 0 { // no msg
			continue
		}
		load := (len(l.cmsgC) * 100) / cap(l.cmsgC) // load percentage
		if c := l.c.get(); c != nil && !isNil(c) {  // look for l.c on every msg
			switch m.t {
			case NONE:
				// drop
			case VVERBOSE, VERBOSE, DEBUG, INFO:
				if load < 95 {
					for _, line := range m.m {
						c.Log(m.t, line)
					}
					recycleAll(m.ml)
					continue
				} // drop
			case WARN, ERROR:
				if load < 5 {
					if d := l.cskips.Swap(0); d > 0 {
						bp, bpsl := l.fmtmsg(WARN, "backpressure... dropped %d msgs", d)
						for _, line := range bp {
							c.Log(WARN, line)
						}
						recycleAll(bpsl)
					}
				}
				if load < 99 {
					for _, line := range m.m {
						c.Log(m.t, line)
					}
					recycleAll(m.ml)
					continue
				} // drop
			case STACKTRACE:
				for _, line := range m.m {
					c.Log(m.t, line)
				}
				recycleAll(m.ml)
				continue
			case USR:
				for _, line := range m.m {
					c.Log(m.t, line)
				}
				recycleAll(m.ml)
				continue
			}
		} // dropped
		recycleAll(m.ml)
		l.cskips.Add(1)
	}
}

// consoleQueue sends msg m to l.msgC, dropping if full.
func (l *simpleLogger) consoleQueue(m *conMsg) {
	select {
	case l.cmsgC <- m:
	default:
		recycleAll(m.ml) // channel full; recycle slabs
	}
}

func (l *simpleLogger) Usr(msg string) {
	if l.level <= USR {
		if count := l.incrStCount(msg); count > similarUsrMsgThreshold {
			return
		}
		l.consoleQueue(&conMsg{m: []Logmsg{(Logmsg)(msg)}, t: USR})
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
	msgs, slabs := l.fmtmsg(STACKTRACE, msg, args...)
	for _, line := range msgs {
		l.err(at+nextframe, line)
	}
	recycleAll(slabs)
	os.Exit(1)
}

// emitStack sends stacktrace to console or log.
// Empty msgs are ignored. Log level (ex: "F ") is
// prepend to each log line when sent to console.
func (l *simpleLogger) emitStack(at int, msgs ...string) {
	sendtoconsole := at <= callerat
	c := l.c.get()
	hasc := c != nil && !isNil(c)

	for _, msg := range msgs {
		if len(msg) <= 0 {
			continue
		}
		if !sendtoconsole {
			l.err(at+nextframe, msg)
		} else if hasc {
			// c.Stack() on the same go routine, since
			// the caller (ex: core.Recover) may exit
			// immediately once simpleLogger.Stack() returns
			c.Log(STACKTRACE, (Logmsg)(msg))
		} else {
			// msg, which is unsafely type-coerced from []byte,
			// is pooled; but the caller owns []byte and so it
			// cannot be used asynchronously (ex: over channels).
			// l.toConsole(&conMsg{msg, STACKTRACE})
			l.cskips.Add(1)
			break // terminate the loop
		}
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
	msg = msg + " (#" + strconv.FormatUint(uint64(count), 10) + ")"
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
	trace := unsafe.String(unsafe.SliceData(scratch), n)
	l.emitStack(at, msg, trace, prev)
}

func (l *simpleLogger) queued(all bool) (appendix string) {
	maxlines := qSize
	if !all {
		maxlines = minQSize
	}
	i := 0
	// todo: interned strings github.com/golang/go/issues/62483
	lines := make([]string, maxlines)
	for _, a := range l.q.All() {
		if a != nil && len(*a) > 0 {
			// yolo: possible 'a' points to a recycled byte
			lines[i] = unsafe.String(unsafe.SliceData(*a), len(*a))
			i++
		}
		if i >= len(lines) {
			break
		}
	}
	if i > 0 {
		// strings.Join creates a new str
		appendix = strings.Join(lines[:i], "\n")
	}
	return
}

func (l *simpleLogger) fmtmsg(lvl LogLevel, f string, args ...any) ([]Logmsg, []*[]byte) {
	return l.fmtmsg2(lvl, "", f, args...)
}

func (l *simpleLogger) fmtmsg2(lvl LogLevel, t, f string, args ...any) (msgs []Logmsg, slabs []*[]byte) {
	level := lvl.s()
	tag := l.tag

	if len(f) <= 0 {
		s := level + tag + "<empty>"
		return []Logmsg{s}, nil
	}
	defer func() {
		// update per-level counters
		l.ncount[lvl].Add(uint64(len(msgs)))
		for _, line := range msgs {
			l.nbytes[lvl].Add(uint64(len(line)))
		}
	}()

	if len(args) > 0 {
		f = fmt.Sprintf(f, args...) // excl tag+level
	} // else: fast path: no format args, single slab pass
	tlen := 0
	if len(t) > 0 {
		tlen = len(t) + 1 // +1 for the '\t' separator
	}
	if len(f)+tlen < charsPerLine-len(level)-len(tag) {
		n := len(level) + len(tag) + len(f) + tlen
		ptr := obtain(n)
		buf := (*ptr)[:n]
		off := 0
		copy(buf[off:], level)
		off += len(level)
		copy(buf[off:], tag)
		off += len(tag)
		if len(t) > 0 {
			if prependTrace {
				copy(buf[off:], t)
				off += len(t)
				buf[off] = '\t'
				off++
				copy(buf[off:], f)
			} else {
				copy(buf[off:], f)
				off += len(f)
				buf[off] = '\t'
				off++
				copy(buf[off:], t)
			}
		} else {
			copy(buf[off:], f)
		}
		*ptr = buf
		return []Logmsg{b2msg(buf)}, []*[]byte{ptr}
	}
	return l.splitlines(lvl, t, f)
}

func (l *simpleLogger) splitlines(lvl LogLevel, t, f string) ([]Logmsg, []*[]byte) {
	level := lvl.s()
	tag := l.tag
	prefix := len(level) + len(tag)
	chunk := max(charsPerLine-prefix, 1)

	// join trace and message body
	var msg string
	if prependTrace {
		if len(t) > 0 {
			msg = t + "\t" + f
		} else {
			msg = f
		}
	} else {
		if len(t) > 0 {
			msg = f + "\t" + t
		} else {
			msg = f
		}
	}

	// estimate number of output lines
	est := (len(msg)+chunk-1)/chunk + strings.Count(msg, "\n")
	msgs := make([]Logmsg, 0, est)
	slabs := make([]*[]byte, 0, est)

	// will iterate once on msg if "\n" is not present: go.dev/play/p/_fNaqiDll2A
	for line := range strings.SplitSeq(msg, "\n") {
		if len(line) == 0 { // skip empty segments (trailing/consecutive \n)
			continue
		}
		for i := 0; i < len(line); i += chunk {
			seg := line[i:min(i+chunk, len(line))]
			n := prefix + len(seg)
			ptr := obtain(n)
			buf := (*ptr)[:n]
			copy(buf, level)
			copy(buf[len(level):], tag)
			copy(buf[prefix:], seg)
			*ptr = buf
			msgs = append(msgs, b2msg(buf))
			slabs = append(slabs, ptr)
		}
	}
	return msgs, slabs
}

// out logs to stdout and pushes msg into ring buffer.
// ref: github.com/golang/mobile/blob/c713f31d/internal/mobileinit/mobileinit_android.go#L51
func (l *simpleLogger) out(msg string) {
	if runtime.GOOS == "android" {
		l.x.Write(unsafe.Slice(unsafe.StringData(msg), len(msg)))
	} else {
		_ = l.o.Output(0 /*not used*/, msg) // may error
	}
}

// push splits msg on newlines and pushes each non-empty line into the
// ring buffer individually. Since charsPerLine=800, each line fits in a
// LB1024 slab, so the pool never allocates oversized slabs.
func (l *simpleLogger) push(msg string) {
	// TODO? push from where split already happens rather than doing again
	// TODO: slog
	// will iterate at least once
	for line := range strings.SplitSeq(msg, "\n") {
		if len(line) <= 0 {
			continue
		}
		ptr := obtain(len(line))
		buf := (*ptr)[:len(line)]
		copy(buf, line)
		*ptr = buf
		if !l.q.Push(ptr) {
			recycle(ptr) // ring dropped it; return slab to pool
		}
	}
}

// err logs to stderr and pushes msg into ring buffer.
func (l *simpleLogger) err(at int, msg string) {
	if l.callerdepth > 0 {
		_, file := caller(at + nextframe)
		msg = file + msg
	}
	if runtime.GOOS == "android" {
		l.x.Write(unsafe.Slice(unsafe.StringData(msg), len(msg)))
	} else {
		_ = l.e.Output(0 /*unused*/, msg) // may error
	}
	l.push(msg)
}

func caller(at int) (pc uintptr, who string) {
	return caller2(at+nextframe, ":", ": ")
}

func caller2(at int, sep1, sep2 string) (pc uintptr, who string) {
	pc, file, line, _ := runtime.Caller(at)
	if len(file) <= 0 {
		file = fileunknown
	} else {
		file = shortfile(file) + sep1 + strconv.Itoa(line) + sep2
	}
	return pc, file
}

var nopcs = []uintptr{0}
var nofiles = []string{fileunknown}

// go.dev/play/p/h9Woqcp0Xz0
// go traceback is expensive:
// blog.felixge.de/reducing-gos-execution-tracer-overhead-with-frame-pointer-unwinding/
// go.dev/blog/execution-traces-2024
func callers(at, until int, sep1, sep2 string) (pcs []uintptr, files []string, skipped int) {
	if until <= 0 {
		return nopcs, nofiles, 0
	} else if until == 1 {
		pc, who := caller2(at+nextframe, sep1, "")
		return []uintptr{pc}, []string{who}, 0
	}

	rpc := make([]uintptr, until)
	n := runtime.Callers(at+nextframe, rpc)
	if n < 1 {
		return nopcs, nofiles, until
	}

	pcs = make([]uintptr, 0, until)
	files = make([]string, 0, until)
	frames := runtime.CallersFrames(rpc[:n])
	for i := range until {
		frame, more := frames.Next()
		pc := frame.PC // may be 0
		file := frame.File
		line := frame.Line
		fn := frame.Function
		if len(file) <= 0 { // more is false when file is empty
			file = fileunknown
		} else {
			file = shortfile(file) + sep1 + strconv.Itoa(line)
		}
		if len(fn) <= 0 {
			fn = callerunknown
		} else {
			// ex: fn = "github.com/celzero/firestack/intra/dnsx.ChooseHealthyProxyHostPort"
			fn = shortfile(fn)
			fn = shortfn(fn)
		}

		file += sep2 + fn
		pcs = append(pcs, pc)
		files = append(files, file)
		if !more {
			skipped = until - (i + 1)
			break
		}
	}
	return
}

func tracecaller(s string) bool {
	if len(s) <= 0 || s == fileunknown || s == callerunknown {
		return false
	}
	if strings.HasSuffix(s, callerunknown) && strings.HasPrefix(s, fileunknown) {
		return false
	}
	// ex: asm_arm64.s:1223>async.go:49>async.go:121>proxy.go:789
	if strings.Contains(s, "asm_") && strings.Contains(s, ".s") {
		return false // asm files are not useful
	}
	return true
}

// b2msg creates a Logmsg from a byte slice without copying.
// github.com/golang/go/issues/19367
func b2msg(b []byte) Logmsg {
	if len(b) <= 0 {
		return ""
	}
	return (Logmsg)(unsafe.String(unsafe.SliceData(b), len(b)))
}

// splitmsg parses the two-character level prefix prepended by msgstr
// ("D ", "I ", "W ", "E ") and returns the corresponding LogLevel
// together with the message with that prefix stripped.
// If the prefix is not recognised, INFO and the original slice are returned.
func splitmsg(p []byte) (LogLevel, Logmsg) {
	if len(p) >= 2 && p[1] == ' ' {
		switch p[0] {
		case 'Y':
			return VVERBOSE, b2msg(p[2:])
		case 'V':
			return VERBOSE, b2msg(p[2:])
		case 'D':
			return DEBUG, b2msg(p[2:])
		case 'I':
			return INFO, b2msg(p[2:])
		case 'W':
			return WARN, b2msg(p[2:])
		case 'E':
			return ERROR, b2msg(p[2:])
		case 'F':
			return STACKTRACE, b2msg(p[2:])
		case 'U':
			return USR, b2msg(p[2:])
		case ' ':
			return NONE, "" // drop
		default: // may be "?"
		}
	}
	return INFO, b2msg(p)
}

// shortfile strips the last path component from a file path.
func shortfile(file string) string {
	if i := strings.LastIndexByte(file, '/'); i >= 0 {
		file = file[i+1:]
	}
	return file
}

// shortfn strips the package and receiver type from a fully-qualified
// function name, keeping only the function name itself.
// ex: "ipn.(*proxifier).RegisterWin" >> "RegisterWin"
// ex: "rpn.makeWsWg" >> "makeWsWg"
func shortfn(fn string) string {
	if i := strings.LastIndexByte(fn, '.'); i >= 0 {
		fn = fn[i+1:]
	}
	return fn
}

func (l *simpleLogger) writelog(lvl LogLevel, at int, msg string, args ...any) {
	ll := l.level <= lvl
	cc := l.clevel <= lvl

	if ll || cc {
		var pc uintptr
		var file1 string
		if l.callerdepth == maxCallerDepth {
			pc, file1 = caller(at + nextframe)
		} else {
			// skip expensive runtime.Caller; fast-hash up to first 12 chars of msg
			n := min(len(msg), 12)
			file1 = msg[:n]
			pc = uintptr(fhash(unsafe.Slice(unsafe.StringData(msg), n)))
		}
		var trace strings.Builder

		isspam := l.spammy(lvl, pc)
		if isspam {
			l.skips[lvl].Add(1)
		}

		if n := l.skips[lvl].Load(); n > spammsgThreshold[lvl] {
			swapped := l.skips[lvl].CompareAndSwap(n, 0)
			if swapped && (cc || ll) {
				spammsgs, spamslabs := l.fmtmsg(lvl, file1+"spammy... %d msgs; dropped? %t", n, !spamConsole)
				if ll {
					for _, line := range spammsgs {
						l.out(line)
					}
				}
				// print spammsg only if spamming is not allowed
				if cc && !spamConsole {
					l.consoleQueue(&conMsg{m: spammsgs, ml: spamslabs, t: lvl})
				} else {
					recycleAll(spamslabs)
				}
			}
		}

		// ex: go_backendmain.go:6895@_cgoexp_d123334b966f_proxybackend_Rpn_RegisterWin
		// > go_backendmain.go:7120@main.proxybackend_Rpn_RegisterWin
		// > proxies.go:1271@ipn.(*proxifier).RegisterWin
		// > proxies.go:1296@ipn.(*proxifier).registerWin
		// > yegor.go:1868@rpn.(*BaseClient).MakeWsWgFrom
		// > yegor.go:1790@rpn.(*BaseClient).MakeWsWg
		// > yegor.go:1809@rpn.makeWsWg
		// > yegor.go:1602@rpn.genWgConfs
		_, x, _ := callers(at+nextframe, int(l.callerdepth), ":", "@")

		hasAtleastOneTracedCaller := tracecaller(x[0])

		switch lvl {
		case USR, STACKTRACE, NONE: // no-op
		case VVERBOSE:
			if len(x) >= 10 && tracecaller(x[9]) {
				trace.WriteString(x[9])
				trace.WriteByte('>')
			}
			fallthrough
		case VERBOSE:
			if len(x) >= 9 && tracecaller(x[8]) {
				trace.WriteString(x[8])
				trace.WriteByte('>')
			}
			fallthrough
		case DEBUG, ERROR, WARN, INFO:
			if len(x) >= 8 && tracecaller(x[7]) {
				trace.WriteString(x[7])
				trace.WriteByte('>')
			}
			if len(x) >= 7 && tracecaller(x[6]) {
				trace.WriteString(x[6])
				trace.WriteByte('>')
			}
			if len(x) >= 6 && tracecaller(x[5]) {
				trace.WriteString(x[5])
				trace.WriteByte('>')
			}
			if len(x) >= 5 && tracecaller(x[4]) {
				trace.WriteString(x[4])
				trace.WriteByte('>')
			}
			// err
			if len(x) >= 4 && tracecaller(x[3]) {
				trace.WriteString(x[3])
				trace.WriteByte('>')
			}
			// warn
			if len(x) >= 3 && tracecaller(x[2]) {
				trace.WriteString(x[2])
				trace.WriteByte('>')
			}
			// info
			if len(x) >= 2 && tracecaller(x[1]) {
				trace.WriteString(x[1])
				trace.WriteByte('>')
			}
			fallthrough
		default:
			if hasAtleastOneTracedCaller { // x[0] == file1 without fn info
				trace.WriteString(x[0])
			}
		}

		msgs, slabs := l.fmtmsg2(lvl, trace.String(), msg, args...)

		if ll {
			// go's internal logger grabs mutex before every write
			for _, line := range msgs {
				l.out(line)
			}
		}
		if cc && (!isspam || spamConsole) {
			l.consoleQueue(&conMsg{m: msgs, ml: slabs, t: lvl})
		} else {
			recycleAll(slabs)
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

	v := (l.clock.l2[lvl][bkt]).v()

	// reset if pc clock (l2) out ticks level clock (l1);
	// ie, t has probably overflowed to next generation
	// and in that generation, bkt has not yet born.
	// and so reset bkt to 0 or any value < t
	if v > t {
		resyncd := (l.clock.l2[lvl][bkt]).cas(t, 0) // set to t/2?
		if resyncd {
			// age bkt when not spammy
			(l.clock.l2[lvl][bkt]).inc()
			return false // not spammy
		} // else: someone else won the race
		resyncAttempts++
		if resyncAttempts <= 3 {
			goto top
		} // else: so many calls that atomic updates won't go through
		// TODO? assume spammy as that's most likely to be the case
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
	y = uint16(v) > tt
	if !y { // age bkt when not spammy
		(l.clock.l2[lvl][bkt]).inc()
	}
	return
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

// Metrics returns current logger and pool statistics as a formatted string.
func (l *simpleLogger) Metrics() *LogStat {
	s := l.logstat()
	return &s
}

// Hist writes items from recents q to w, one per line.
func (l *simpleLogger) Hist(w io.Writer) (n int) {
	for _, ptr := range l.q.All() {
		if ptr != nil {
			if sz := len(*ptr); sz > 0 {
				w.Write(*ptr)
				w.Write([]byte{'\n'})
				n += sz
			}
		}
	}
	return
}

// logstat snapshots the current logger state into a LogStat struct.
func (l *simpleLogger) logstat() LogStat {
	s := LogStat{
		Tag:          l.tag,
		Level:        l.level,
		ConsoleLvl:   l.clevel,
		CallerDepth:  l.callerdepth,
		ConsoleDrops: l.cskips.Load(),
		RingSize:     l.q.Len(),
	}

	for i := LogLevel(0); i <= NONE; i++ {
		s.Count[i] = l.ncount[i].Load()
		s.Bytes[i] = l.nbytes[i].Load()
		s.Skipped[i] = l.skips[i].Load()
		s.ClockL1[i] = (l.clock.l1[i]).v()
	}

	s.PoolGets, s.PoolNews, s.PoolPuts, s.PoolDrops = logpoolStats()

	return s
}

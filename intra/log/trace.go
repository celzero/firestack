// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"container/list"
	"errors"
	"fmt"
	"hash/maphash"
	"strconv"
	"sync"
)

// Per-key log tracing.
//
// VV3 et al log as usual, but also record every processed line into a
// LogStore keyed by an opaque uint64. Glogger looks up the logstoremap
// and adds each line they process to it.
// The map retains at most logmapcap stores and evicts the oldest key first.
//
// LogStore is backed by pooled []byte slabs from logpool.go. The
// store owns the slabs handed to it via Put; they are returned to the
// pool when a store is recycled or when they are evicted
// from the underlying ring buffer (drop-oldest).

// LogStore accumulates formatted log lines for a single trace key,
// backed by pooled []byte slices from logpool.go.
type LogStore interface {
	// Get returns all accumulated lines, oldest first, or nil if this
	// store has been consumed or recycled. Get is a read-only peek: it
	// may be called repeatedly. The returned bytes are valid until the
	// store is released or evicted from the bounded global map.
	Get() *[][]byte
	// Put adds a single formatted log line to this store. The slab
	// (*[]byte from obtain, see logpool.go) is owned by the store once
	// put; the oldest line may be evicted to make room.
	// Put is a no-op if store is consumed or recycled.
	Put(*[]byte)
}

// defaultTraceCap is the default max no. of lines a LogStore keeps.
const defaultTraceCap = 256

// logmapcap is the maximum number of live trace keys.
const logmapcap = defaultTraceCap

var (
	logstoremu  sync.Mutex                       // guards the store map, FIFO, and logstorecap
	logstoremap = make(map[uint64]LogStore)      // key -> live LogStore
	logstoreord = list.New()                     // keys in store-creation order; oldest first
	logstoreidx = make(map[uint64]*list.Element) // key -> position in logstoreorder
	logstorecap = defaultTraceCap                // cap for stores created henceforth
)

// logstore is the default LogStore: a fixed-size ring of pooled slabs
// that drops the oldest line beyond its cap.
type logstore struct {
	mu   sync.Mutex
	b    []*[]byte // ring of pooled slabs; nil slots are empty
	head int       // index at which the next slab is written
	n    int       // no. of live slabs in b
	dead bool      // consumed or recycled: Get and Put are no-ops
}

var _ LogStore = (*logstore)(nil)

func mklogstore(capacity int) *logstore {
	if capacity <= 0 {
		capacity = defaultTraceCap
	}
	return &logstore{b: make([]*[]byte, capacity)}
}

// Get implements [LogStore].
func (s *logstore) Get() *[][]byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dead {
		return nil // no-op on consumed or recycled store
	}
	out := make([][]byte, 0, s.n)
	if s.n <= 0 {
		return &out
	}
	start := (s.head - s.n + len(s.b)) % len(s.b) // oldest
	for i := range s.n {
		if p := s.b[(start+i)%len(s.b)]; p != nil {
			out = append(out, *p) // zero-copy peek into pooled slab
		}
	}
	return &out
}

// Put implements [LogStore].
func (s *logstore) Put(b *[]byte) {
	if s == nil || b == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dead {
		recycle(b) // a racing put transfers ownership even if this store was evicted
		return     // no-op on consumed or recycled store
	}
	old := s.b[s.head] // oldest slab once the ring is full, else nil
	s.b[s.head] = b
	s.head = (s.head + 1) % len(s.b)
	if s.n == len(s.b) {
		recycle(old) // drop-oldest: evicted slab returns to the pool
	} else {
		s.n++
	}
}

// release marks this store consumed or recycled and returns its pooled
// slabs to the pool (logpool.go).
func (s *logstore) release() (released bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dead {
		return
	}
	s.dead = true
	for i := range s.b {
		if p := s.b[i]; p != nil {
			released = true
			recycle(p)
			s.b[i] = nil
		}
	}
	s.n = 0
	s.head = 0
	return
}

// setCap resizes the ring to n lines, evicting (and recycling) the
// oldest lines beyond n.
func (s *logstore) setCap(n int) {
	if n <= 0 {
		n = defaultTraceCap
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dead || n == len(s.b) {
		return
	}
	keep := min(n, s.n) // the newest lines survive
	start := (s.head - keep + len(s.b)) % len(s.b)
	// recycle the older lines that don't make the cut
	dropn := s.n - keep
	if dropn > 0 {
		dstart := (s.head - s.n + len(s.b)) % len(s.b)
		for i := range dropn {
			if p := s.b[(dstart+i)%len(s.b)]; p != nil {
				recycle(p)
			}
		}
	}
	nb := make([]*[]byte, n)
	for i := range keep {
		nb[i] = s.b[(start+i)%len(s.b)]
	}
	s.b = nb
	s.n = keep
	s.head = keep % n
}

// storefor returns the LogStore for key, creating one if none exists.
func storefor(key uint64) LogStore {
	logstoremu.Lock()
	defer logstoremu.Unlock()

	if s := logstoremap[key]; s != nil {
		return s
	}
	if len(logstoremap) >= logmapcap {
		if oldest := logstoreord.Front(); oldest != nil {
			oldkey := oldest.Value.(uint64)
			oldstore := logstoremap[oldkey]
			delete(logstoremap, oldkey)
			delete(logstoreidx, oldkey)
			logstoreord.Remove(oldest)
			if s, ok := oldstore.(*logstore); ok {
				s.release()
			}
		}
	}
	s := mklogstore(logstorecap)
	logstoremap[key] = s
	logstoreidx[key] = logstoreord.PushBack(key)
	return s
}

// putmsg copies msg into a pooled slab and adds it to the [LogStore] for
// key. No-op if key is 0.
func putmsg(key uint64, msg string) {
	if key == 0 || len(msg) <= 0 {
		return
	}
	n := len(msg)
	ptr := obtain(n)
	buf := (*ptr)[:n]
	copy(buf, msg)
	*ptr = buf
	storefor(key).Put(ptr)
}

// GetAll returns the LogStore trace for key, if any.
// Returns nil if no [LogStore] exists for key.
func GetAll(key uint64) LogStore {
	logstoremu.Lock()
	defer logstoremu.Unlock()

	return logstoremap[key]
}

// GetAll returns the LogStore trace for key, if any.
// Returns nil if no [LogStore] exists for key.
func GetAllStr(key string) LogStore {
	return GetAll(hex2uint64(key))
}

// Release removes the LogStore for key, if any, from the global map and
// recycles its pooled byte slices.
func Release(key uint64) bool {
	logstoremu.Lock()
	ls := logstoremap[key]
	delete(logstoremap, key)
	if elem := logstoreidx[key]; elem != nil {
		logstoreord.Remove(elem)
		delete(logstoreidx, key)
	}
	logstoremu.Unlock()

	if ls != nil {
		if s, ok := ls.(*logstore); ok {
			return s.release()
		}
	}
	return false
}

func ReleaseStr(key string) {
	Release(hex2uint64(key))
}

// SetTraceCap sets the max number of lines each LogStore accumulates,
// dropping the oldest beyond that. Applies to live stores too.
// Values <= 0 restore [defaultTraceCap].
func SetTraceCap(n int) {
	if n <= 0 {
		n = defaultTraceCap
	}
	logstoremu.Lock()
	defer logstoremu.Unlock()

	logstorecap = n
	for _, ls := range logstoremap {
		if s, ok := ls.(*logstore); ok {
			s.setCap(n)
		}
	}
}

// TraceCap returns the max number of lines each LogStore accumulates.
func TraceCap() int {
	logstoremu.Lock()
	defer logstoremu.Unlock()

	return logstorecap
}

// logstoreStats returns a consistent snapshot of the global trace-store indexes.
func logstoreStats() (mapSize, orderSize, indexSize, mapCap int) {
	logstoremu.Lock()
	defer logstoremu.Unlock()

	return len(logstoremap), logstoreord.Len(), len(logstoreidx), logmapcap
}

// VV3 logs a very verbose message, traced to the LogStore for key (if any).
func VV3(key uint64, msg string, args ...any) {
	Glogger.VeryVerbosef(key, callerat, msg, args...)
}

// V3 logs a verbose message, traced to the LogStore for key (if any).
func V3(key uint64, msg string, args ...any) {
	Glogger.Verbosef(key, callerat, msg, args...)
}

// D3 logs a debug message, traced to the LogStore for key (if any).
func D3(key uint64, msg string, args ...any) {
	Glogger.Debugf(key, callerat, msg, args...)
}

// I3 logs an info message, traced to the LogStore for key (if any).
func I3(key uint64, msg string, args ...any) {
	Glogger.Infof(key, callerat, msg, args...)
}

// W3 logs a warning message, traced to the LogStore for key (if any).
func W3(key uint64, msg string, args ...any) {
	Glogger.Warnf(key, callerat, msg, args...)
}

// E3 logs an error message, traced to the LogStore for key (if any).
func E3(key uint64, msg string, args ...any) {
	Glogger.Errorf(key, callerat, msg, args...)
}

// U3 logs a user message (notifies the user), traced to the LogStore for key (if any).
func U3(key uint64, msg string) {
	Glogger.Usr(key, msg)
}

// P3 logs a private message, traced to the LogStore for key (if any).
func P3(key uint64, msg string, args ...any) {
	Glogger.Piif(key, callerat, msg, args...)
}

// WE3 logs msg as warning and returns it as an error, traced to the
// LogStore for key (if any).
func WE3(key uint64, msg string, args ...any) (err error) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	Glogger.Warnf(key, callerat, msg)
	return errors.New(msg)
}

// EE3 logs msg as error and returns it as an error, traced to the
// LogStore for key (if any).
func EE3(key uint64, msg string, args ...any) (err error) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	Glogger.Errorf(key, callerat, msg)
	return errors.New(msg)
}

// N3 is a no-op logger.
func N3(uint64, string, ...any) {}

// VV4 logs a very verbose message, tracing it with the hexadecimal key.
func VV4(key string, msg string, args ...any) {
	Glogger.VeryVerbosef(hex2uint64(key), callerat, msg, args...)
}

// V4 logs a verbose message, tracing it with the hexadecimal key.
func V4(key string, msg string, args ...any) {
	Glogger.Verbosef(hex2uint64(key), callerat, msg, args...)
}

// D4 logs a debug message, tracing it with the hexadecimal key.
func D4(key string, msg string, args ...any) {
	Glogger.Debugf(hex2uint64(key), callerat, msg, args...)
}

// I4 logs an info message, tracing it with the hexadecimal key.
func I4(key string, msg string, args ...any) {
	Glogger.Infof(hex2uint64(key), callerat, msg, args...)
}

// W4 logs a warning message, tracing it with the hexadecimal key.
func W4(key string, msg string, args ...any) {
	Glogger.Warnf(hex2uint64(key), callerat, msg, args...)
}

// E4 logs an error message, tracing it with the hexadecimal key.
func E4(key string, msg string, args ...any) {
	Glogger.Errorf(hex2uint64(key), callerat, msg, args...)
}

// U4 logs a user message (notifies the user), tracing it with the hexadecimal key.
func U4(key, msg string) {
	Glogger.Usr(hex2uint64(key), msg)
}

// P4 logs a private message, tracing it with the hexadecimal key.
func P4(key string, msg string, args ...any) {
	Glogger.Piif(hex2uint64(key), callerat, msg, args...)
}

// WE4 logs msg as warning and returns it as an error, tracing it with the hexadecimal key.
func WE4(key string, msg string, args ...any) (err error) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	Glogger.Warnf(hex2uint64(key), callerat, msg)
	return errors.New(msg)
}

// EE4 logs msg as error and returns it as an error, tracing it with the hexadecimal key.
func EE4(key string, msg string, args ...any) (err error) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	Glogger.Errorf(hex2uint64(key), callerat, msg)
	return errors.New(msg)
}

var logidseed = maphash.MakeSeed()

func hex2uint64(h2 string) uint64 {
	if v, verr := strconv.ParseUint(h2, 16, 64); verr == nil {
		return v
	}
	return maphash.Comparable(logidseed, h2)
}

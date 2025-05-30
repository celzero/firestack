// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import (
	"hash/maphash"
	"sync"
	"unique"
	"weak"
)

const (
	internstr         = true
	maxinternattempts = 3 // max no. of times to try load/store interned Gostr
)

type strmap[T any] sync.Map

// pointer to pointer v pointer to Gostr both come out
// with equal behaviour: go.dev/play/p/4qT1JACgdHG
func (s *strmap[T]) get(k unique.Handle[string]) (**T, bool) {
	m := (*sync.Map)(s)
	if w, ok := m.Load(k); ok {
		if v, ok := w.(weak.Pointer[T]); ok {
			if out := v.Value(); out != nil {
				return &out, true
			} else { // if weak value is gone, delete key
				m.CompareAndDelete(k, w)
			}
		}
	}
	return nil, false
}

func (s *strmap[T]) put(k unique.Handle[string], v **T) (**T, bool) {
	m := (*sync.Map)(s)
	w := weak.Make(*v)

	tries := 0
reload:
	if tries > maxinternattempts { // circuit breaker
		return nil, false
	}
	tries += 1

	x, _ := m.LoadOrStore(k, w)
	if v, ok := x.(weak.Pointer[T]); ok {
		// if the value is already present, return it
		if out := v.Value(); out != nil {
			return &out, true
		} else { // if weak value is gone, delete key
			m.CompareAndDelete(k, w)
			goto reload
		}
	}
	return nil, false
}

var (
	interns  = &strmap[Gostr]{}  // unique.Handle[string] => Gostr
	interns2 = &strmap[Gostr2]{} // unique.Handle[string] => Gostr2

	mseed = maphash.MakeSeed()
)

// String wrapped in struct Gomsg is a workaround for:
// github.com/golang/go/issues/46893
type Gomsg struct {
	S string
}

func MsgOf(v string) *Gomsg {
	if len(v) == 0 {
		return nil
	}
	return &Gomsg{S: v}
}

// Gostr2 is like Gostr but the raw string is not exported to Java/Kotlin.
type Gostr2 struct {
	v unique.Handle[string]
	// hash of Gostr's string (exported for java/kt equals())
	H int64
	// length of Gostr's string (exported for java/kt hashCode())
	L int
}

// Gostr wraps a go string.
type Gostr struct {
	S string
}

// Do not use from Java/Kotlin.
func (s *Gostr) String() string {
	if s == nil {
		return ""
	}
	return s.S
}

func StrOf(v string) *Gostr {
	return strof(v)
}

func StrOf2(v string) *Gostr2 {
	return strof2(v)
}

func strof(v string) (r *Gostr) {
	if len(v) == 0 {
		return nil
	}
	hdl := unique.Make(v)
	if internstr {
		if s, ok := interns.get(hdl); ok {
			r = *s
		}
		if r == nil {
			new := &Gostr{S: v}
			if s, ok := interns.put(hdl, &new); ok {
				r = *s
			}
		}
		// TODO: panic if r == nil && v != ""?
		return r // may be nil
	}
	return &Gostr{S: v}
}

func strof2(v string) (r *Gostr2) {
	if len(v) == 0 {
		return nil
	}
	hdl := unique.Make(v) // go.dev/play/p/LFqxCEZSo62
	if internstr {
		if s, ok := interns2.get(hdl); ok {
			r = *s
		}
		if r == nil {
			new := &Gostr2{v: hdl, H: hashstr(v), L: len(v)}
			if s, ok := interns2.put(hdl, &new); ok {
				r = *s
			}
		}
		// TODO: panic if r == nil && v != ""?
		return r // may be nil
	}
	return &Gostr2{v: hdl, H: hashstr(v), L: len(v)}
}

// Do not use from Java/Kotlin; instead call M() and use Gomsg.S
func (s *Gostr2) V() string {
	if s == nil {
		return ""
	}
	return s.v.Value()
}

var emptyGomsg = &Gomsg{S: ""}

func (s *Gostr2) M() *Gomsg {
	if s != nil && s.v.Value() != "" {
		return &Gomsg{S: s.v.Value()}
	}
	return emptyGomsg
}

func OfFunc[T *Gostr2 | *Gobyte, R string | []byte](f func() (R, error)) (T, error) {
	v, err := f()
	if err != nil {
		return nil, err
	}
	switch any(v).(type) {
	case string:
		if str, ok := any(v).(string); ok {
			return any(StrOf2(str)).(T), nil
		}
	case []byte:
		if bytes, ok := any(v).([]byte); ok {
			return any(BytesOf(bytes)).(T), nil
		}
	}
	var zero T
	return zero, nil
}

func StrOfFunc(f func() (string, error)) (*Gostr, error) {
	s, err := f()
	if err != nil {
		return nil, err
	}
	return StrOf(s), nil
}

func StrOfFunc1[P any](f func(P) (string, error), p P) (*Gostr, error) {
	s, err := f(p)
	if err != nil {
		return nil, err
	}
	return StrOf(s), nil
}

func StrOfFunc2[P any, Q any](f func(P, Q) (string, error), p P, q Q) (*Gostr, error) {
	s, err := f(p, q)
	if err != nil {
		return nil, err
	}
	return StrOf(s), nil
}

// Gostr & Gobyte are a workaround for:
// github.com/golang/go/issues/46893
type Gobyte struct {
	B []byte
	// hash of Gobyte's bytes (exported for java/kt equals())
	H uint64
	// length of Gobyte's bytes (exported for java/kt hashCode())
	L int
}

func BytesOf(v []byte) *Gobyte {
	if len(v) == 0 {
		return nil
	}
	return &Gobyte{B: v, H: maphash.Bytes(mseed, v), L: len(v)}
}

// Do not use from Java/Kotlin; instead use Gobyte.B.
func (b *Gobyte) V() []byte {
	if b == nil {
		return nil
	}
	return b.B
}

func (b *Gobyte) Len() int {
	if b == nil {
		return 0
	}
	return b.L
}

func BytesOfFunc(f func() ([]byte, error)) (*Gobyte, error) {
	s, err := f()
	if err != nil {
		return nil, err
	}
	return BytesOf(s), nil
}

func hashstr(s string) int64 {
	if len(s) == 0 {
		return 0
	}
	// need to preserve just the bit pattern
	// as uint64 isn't exportable to java/kt
	// while int64 (as long) is.
	return int64(maphash.String(mseed, s))
}

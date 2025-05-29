// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import (
	"sync"
	"unique"
	"weak"
)

const internstr = true

var (
	internmu = new(sync.Mutex)
	interns  = make(map[unique.Handle[string]]weak.Pointer[Gostr])
)

// Gostr & Gobytes are a workaround for:
// github.com/golang/go/issues/46893

type Gostr struct {
	v unique.Handle[string]
}

func (s *Gostr) String() string {
	return s.V()
}

func StrOf(v string) (r *Gostr) {
	if len(v) == 0 {
		return nil
	}

	// go.dev/play/p/LFqxCEZSo62
	hdl := unique.Make(v)
	if internstr {
		internmu.Lock()
		defer internmu.Unlock()

		if s, ok := interns[hdl]; ok {
			r = s.Value()
		}
		if r == nil {
			r = &Gostr{v: hdl}
			interns[hdl] = weak.Make(r)
		}

		return r
	}
	return &Gostr{v: hdl}
}

func (s *Gostr) V() string {
	if s == nil {
		return ""
	}
	return s.v.Value()
}

func (s *Gostr) Len() int {
	return len(s.V())
}

func OfFunc[T *Gostr | *Gobyte, R string | []byte](f func() (R, error)) (T, error) {
	v, err := f()
	if err != nil {
		return nil, err
	}
	switch any(v).(type) {
	case string:
		if str, ok := any(v).(string); ok {
			return any(StrOf(str)).(T), nil
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

type Gobyte struct {
	v []byte
}

func BytesOf(v []byte) *Gobyte {
	return &Gobyte{v: v}
}

func (b *Gobyte) V() []byte {
	if b == nil {
		return nil
	}
	return b.v
}

func (b *Gobyte) Len() int {
	return len(b.V())
}

func BytesOfFunc(f func() ([]byte, error)) (*Gobyte, error) {
	s, err := f()
	if err != nil {
		return nil, err
	}
	return BytesOf(s), nil
}

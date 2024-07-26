package core

import (
	"sync"
	"time"

	sieve "github.com/opencoff/go-sieve"
)

const (
	capacity = 2048
	lifetime = 30 * time.Second
)

type sval[T any] struct {
	exp time.Time
	v   T
}

type Sieve[K comparable, V any] struct {
	sync.RWMutex
	c *sieve.Sieve[K, sval[V]]
	t time.Duration
}

// NewDefaultSieve returns a new Sieve with default capacity (2048) and lifetime (30s).
func NewDefaultSieve[K comparable, V any]() *Sieve[K, V] {
	return NewSieve[K, V](capacity, lifetime)
}

// NewSieve returns a new Sieve with the given capacity and lifetime.
func NewSieve[K comparable, V any](sz int, lifetime time.Duration) *Sieve[K, V] {
	return &Sieve[K, V]{
		c: sieve.New[K, sval[V]](sz),
		t: lifetime,
	}
}

func (s *Sieve[K, V]) Get(k K) (V, bool) {
	s.RLock()
	defer s.RUnlock()
	r, ok := s.c.Get(k)
	if !ok || time.Until(r.exp) < 0 {
		var zz V // zero value
		return zz, false
	}
	return r.v, true
}

func (s *Sieve[K, V]) Put(k K, v V) (replaced bool) {
	s.Lock()
	defer s.Unlock()
	return s.c.Add(k, sval[V]{
		exp: time.Now().Add(s.t),
		v:   v,
	})
}

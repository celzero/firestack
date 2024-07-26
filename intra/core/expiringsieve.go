package core

import (
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

// Sieve is a thread-safe map with expiring keys and fixed capacity.
// Eviction is based on the SIEVE algorithm described in:
// yazhuozhang.com/assets/pdf/nsdi24-sieve.pdf
type Sieve[K comparable, V any] struct {
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

// Get returns the value associated with the given key,
// and a boolean indicating whether the key was found.
func (s *Sieve[K, V]) Get(k K) (V, bool) {
	r, ok := s.c.Get(k)
	if !ok || time.Until(r.exp) < 0 {
		var zz V // zero value
		return zz, false
	}
	return r.v, true
}

func (s *Sieve[K, V]) Put(k K, v V) (replaced bool) {
	return s.c.Add(k, sval[V]{
		exp: time.Now().Add(s.t),
		v:   v,
	})
}

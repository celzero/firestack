package dialers

import (
	"net/netip"
	"sync"
	"time"

	sieve "github.com/opencoff/go-sieve"
)

type ttlval struct {
	exp     time.Time
	ttlSecs int
}

type ttlmap struct {
	sync.RWMutex
	c *sieve.Sieve[netip.Addr, ttlval]
}

const (
	capacity = 2048
	lifetime = 30 * time.Second
)

var ttlcache ttlmap = ttlmap{
	c: sieve.New[netip.Addr, ttlval](capacity),
}

// getTTL returns the TTL for the given IP address, if present.
func getTTL(ip netip.Addr) (int, bool) {
	ttlcache.RLock()
	defer ttlcache.RUnlock()
	r, ok := ttlcache.c.Get(ip)
	if !ok || time.Until(r.exp) < 0 {
		return 0, false
	}
	return r.ttlSecs, true
}

// putTTL stores the TTL for the given IP address for a limited time (30s).
func putTTL(ip netip.Addr, ttl int) {
	ttlcache.Lock()
	defer ttlcache.Unlock()
	ttlcache.c.Add(ip, ttlval{
		exp:     time.Now().Add(lifetime),
		ttlSecs: ttl,
	})
}

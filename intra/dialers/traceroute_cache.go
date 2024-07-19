package dialers

import (
	sieve "github.com/opencoff/go-sieve" //This line is copied from dnscrypt-proxy,
	"net"
	"sync"
	"time"
)

type cachedResult struct {
	expiration int64 //in seconds
	ttl        int
}

type cachedResults struct {
	sync.RWMutex
	ipv4Cache *sieve.Sieve[[4]byte, cachedResult]
	ipv6Cache *sieve.Sieve[[8]byte, cachedResult]
}

const (
	defaultCapacity = 512
	defaultStaleTtl = 30 // in seconds
)

var globalCache cachedResults

func queryTracerouteResult(ip net.IP) (int, bool) {
	isIPv6 := ip.To4() == nil
	globalCache.RLock()
	defer globalCache.RUnlock()
	if globalCache.ipv4Cache == nil || globalCache.ipv6Cache == nil {
		return 0, false
	}
	var (
		r  cachedResult
		ok bool
	)
	if isIPv6 {
		var key [8]byte
		copy(key[:], ip[:8])
		r, ok = globalCache.ipv6Cache.Get(key)
	} else {
		var key [4]byte
		copy(key[:], ip.To4())
		r, ok = globalCache.ipv4Cache.Get(key)
	}
	if !ok {
		return 0, false
	}
	if time.Now().Unix() > r.expiration {
		return 0, false
	}
	return r.ttl, true
}
func addTracerouteResult(ip net.IP, ttl int) {
	isIPv6 := ip.To4() == nil
	result := cachedResult{
		expiration: time.Now().Unix() + defaultStaleTtl,
		ttl:        ttl,
	}
	globalCache.Lock()
	defer globalCache.Unlock()
	if globalCache.ipv4Cache == nil || globalCache.ipv6Cache == nil {
		globalCache.ipv4Cache = sieve.New[[4]byte, cachedResult](defaultCapacity)
		globalCache.ipv6Cache = sieve.New[[8]byte, cachedResult](defaultCapacity)
	}
	if isIPv6 {
		var key [8]byte
		copy(key[:], ip[:8])
		globalCache.ipv6Cache.Add(key, result)
	} else {
		var key [4]byte
		copy(key[:], ip.To4())
		globalCache.ipv4Cache.Add(key, result)
	}
}

package dnsx

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolvLockedUntilUsesRemainingTTL(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	domain := qname(q)

	tid := "tid"
	uid := "uid"
	ttl := time.Now().Add(30 * time.Second)

	realip := netip.MustParseAddr("1.1.1.1")
	algip := netip.MustParseAddr("100.64.0.1")

	xips := NewXips(tid, uid, []netip.Addr{realip}, nil, ttl)
	if xips == nil {
		t.Fatalf("expected xips")
	}
	xdomains := NewXdomains(tid, uid, []string{domain}, ttl)
	if xdomains == nil {
		t.Fatalf("expected xdomains")
	}

	gw := &dnsgateway{
		alg: map[string]*algans{
			domain + key4 + "0": {
				algip: algip,
				baseans: &baseans{
					ips:     xips,
					domains: xdomains,
					ttl:     ttl,
				},
			},
		},
		nat: make(map[netip.Addr]*baseans),
		ptr: make(map[netip.Addr]*baseans),
	}

	_, _, _, until, _ := gw.resolvLocked(domain, typreal, tid, uid)
	if until <= 0 {
		t.Fatalf("expected positive ttl, got %s", until)
	}

	ans, err := gw.fromInternalCache(tid, uid, q, typreal)
	if err != nil {
		t.Fatalf("expected cache hit, got error %v", err)
	}
	if len(ans.Answer) == 0 {
		t.Fatalf("expected at least one answer")
	}
	if got := ans.Answer[0].Header().Ttl; got < 20 {
		t.Fatalf("expected ttl >= 20s, got %d", got)
	}
}

package ipn

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

type fakeProxy struct{ id string }

type systemMapper struct{}

func (systemMapper) LocalLookup(_ []byte) ([]byte, error) {
	return nil, errors.New("wire lookup not supported")
}
func (systemMapper) Lookup(_ []byte, _ string, _ ...string) ([]byte, error) {
	return nil, errors.New("wire lookup not supported")
}
func (systemMapper) LookupFor(_ []byte, _ string) ([]byte, error) {
	return nil, errors.New("wire lookup not supported")
}
func (systemMapper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
func (systemMapper) LookupNetIPFor(ctx context.Context, network, host, _ string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
func (systemMapper) LookupNetIPOn(ctx context.Context, network, host string, _ ...string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

func (f *fakeProxy) Dial(network, addr string) (protect.Conn, error) { return net.Dial(network, addr) }
func (f *fakeProxy) DialBind(network, local, remote string) (protect.Conn, error) {
	if local == "" {
		return f.Dial(network, remote)
	}
	return net.Dial(network, remote)
}
func (f *fakeProxy) Announce(string, string) (protect.PacketConn, error) {
	return nil, errAnnounceNotSupported
}
func (f *fakeProxy) Accept(string, string) (protect.Listener, error) {
	return nil, errAnnounceNotSupported
}
func (f *fakeProxy) Probe(string, string) (protect.PacketConn, error) {
	return nil, errProbeNotSupported
}
func (f *fakeProxy) Dialer() protect.RDialer                { return f }
func (f *fakeProxy) DialerHandle() uintptr                  { return 0 }
func (f *fakeProxy) Handle() uintptr                        { return 0 }
func (f *fakeProxy) ID() string                           { return f.id }
func (f *fakeProxy) Type() string                         { return NOOP }
func (f *fakeProxy) Router() x.Router                       { return &GWNoVia{} }
func (f *fakeProxy) Client() x.Client                       { return newProxyClient(f) }
func (f *fakeProxy) onNotOK() (bool, bool)                  { return false, true }
func (f *fakeProxy) OnProtoChange(LinkProps) (string, bool) { return "", false }
func (f *fakeProxy) Hop(Proxy, bool) error                  { return nil }
func (f *fakeProxy) Status() int                            { return TOK }
func (f *fakeProxy) GetAddr() string                      { return "" }
func (f *fakeProxy) DNS() string                          { return "" }
func (f *fakeProxy) Ping() bool                             { return true }
func (f *fakeProxy) Pause() bool                            { return false }
func (f *fakeProxy) Resume() bool                           { return false }
func (f *fakeProxy) Stop() error                            { return nil }
func (f *fakeProxy) Refresh() error                         { return nil }

func restoreDefaultURLs(t *testing.T) func() {
	prevTrace, prevWarp := traceURL, warpURL
	prevV4, prevV6 := mullvadV4URL, mullvadV6URL
	traceURL, warpURL = defaultTraceURL, defaultWarpURL
	mullvadV4URL, mullvadV6URL = defaultMullvadV4URL, defaultMullvadV6URL
	return func() {
		traceURL, warpURL = prevTrace, prevWarp
		mullvadV4URL, mullvadV6URL = prevV4, prevV6
	}
}

func newIPv4Server(t *testing.T) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ipv4 listen: %v", err)
	}
	return newServerWithListener(t, ln)
}

func newIPv6Server(t *testing.T) (*httptest.Server, bool) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return nil, false
	}
	return newServerWithListener(t, ln), true
}

func newServerWithListener(t *testing.T, ln net.Listener) *httptest.Server {
	t.Helper()
	handler := http.NewServeMux()
	handler.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("fl=765f119\nloc=US\ncolo=DFW\nip=1.2.3.4\n"))
	})
	handler.HandleFunc("/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ip":"1.2.3.4","country":"United States","city":"Dallas","longitude":-96.8,"latitude":32.8,"organization":"Example Org"}`))
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestProxyClientIP4(t *testing.T) {
	srv := newIPv4Server(t)

	prevTrace, prevMull := traceURL, mullvadV4URL
	traceURL, mullvadV4URL = srv.URL+"/cdn-cgi/trace", srv.URL+"/json"
	defer func() { traceURL, mullvadV4URL = prevTrace, prevMull }()

	p := &fakeProxy{id: "test-ipv4"}
	meta, err := newProxyClient(p).IP4()
	if err != nil {
		t.Fatalf("ip4 err: %v", err)
	}

	if meta.IP != "1.2.3.4" {
		t.Fatalf("ip mismatch: %v", meta.IP)
	}
	if meta.CC != "US" {
		t.Fatalf("cc mismatch: %v", meta.CC)
	}
	if meta.City != "Dallas" {
		t.Fatalf("city mismatch: %v", meta.City)
	}
	if meta.ASNOrg != "Example Org" {
		t.Fatalf("asn org mismatch: %v", meta.ASNOrg)
	}
	if meta.ProviderURL != mullvadV4URL {
		t.Fatalf("provider mismatch: %v", meta.ProviderURL)
	}
}

func TestProxyClientIP6(t *testing.T) {
	srv, ok := newIPv6Server(t)
	if !ok {
		t.Skip("ipv6 not available")
	}

	prevTrace, prevMull := traceURL, mullvadV6URL
	traceURL, mullvadV6URL = srv.URL+"/cdn-cgi/trace", srv.URL+"/json"
	defer func() { traceURL, mullvadV6URL = prevTrace, prevMull }()

	p := &fakeProxy{id: "test-ipv6"}
	meta, err := newProxyClient(p).IP6()
	if err != nil {
		t.Fatalf("ip6 err: %v", err)
	}

	if meta.IP != "1.2.3.4" {
		t.Fatalf("ip mismatch: %v", meta.IP)
	}
	if meta.CC != "US" {
		t.Fatalf("cc mismatch: %v", meta.CC)
	}
	if meta.ProviderURL != mullvadV6URL {
		t.Fatalf("provider mismatch: %v", meta.ProviderURL)
	}
}

func TestProxyClientIP4Live(t *testing.T) {
	defer restoreDefaultURLs(t)()
	skipWarpForTesting = true
	skipTraceForTesting = true
	skipMullvadForTesting = false
	dialers.Mapper(ipmap.NewIPMapFor(systemMapper{}))

	p := &fakeProxy{id: "live-ipv4"}
	meta, err := newProxyClient(p).IP4()
	if err != nil {
		t.Fatalf("live ip4 err: %v", err)
	}

	if meta.IP == "" {
		t.Fatal("live ip4: empty ip")
	}
	if ip, err := netip.ParseAddr(meta.IP); err != nil || !ip.Is4() {
		t.Fatalf("live ip4: not v4 ip: %v", meta.IP)
	}
	if meta.ProviderURL == "" {
		t.Fatal("live ip4: empty provider")
	}
	if strings.Contains(strings.ToLower(meta.ProviderURL), "example.org") {
		t.Fatalf("live ip4: unexpected provider: %v", meta.ProviderURL)
	}
}

func TestProxyClientIP6Live(t *testing.T) {
	defer restoreDefaultURLs(t)()
	skipWarpForTesting = false
	skipTraceForTesting = true
	skipMullvadForTesting = true
	dialers.Mapper(ipmap.NewIPMapFor(systemMapper{}))

	p := &fakeProxy{id: "live-ipv6"}
	meta, err := newProxyClient(p).IP6()

	if err != nil {
		// skip on environments without ipv6 connectivity
		if strings.Contains(err.Error(), "no suitable address") ||
			strings.Contains(strings.ToLower(err.Error()), "ipv6") {
			t.Skipf("ipv6 live lookup skipped: %v", err)
		}
		t.Fatalf("live ip6 err: %v", err)
	}
	t.Log(meta)

	if meta.IP == "" {
		t.Fatal("live ip6: empty ip")
	}
	if ip, err := netip.ParseAddr(meta.IP); err != nil || !ip.Is6() {
		t.Fatalf("live ip6: not v6 ip: %v", meta.IP)
	}
	if meta.ProviderURL == "" {
		t.Fatal("live ip6: empty provider")
	}
}

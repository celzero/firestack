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
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

type fakeProxy struct{ id string }

type systemMapper struct{}

func (systemMapper) Lookup(_ []byte, _ string, _ ...string) ([]byte, error) {
	return nil, errors.New("wire lookup not supported")
}

func (systemMapper) LookupNetIP(ctx context.Context, network, host, _ string, _ ...string) ([]netip.Addr, error) {
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
func (f *fakeProxy) DialerHandle() uint64                   { return core.Nobody }
func (f *fakeProxy) Handle() uint64                         { return core.Nobody }
func (f *fakeProxy) ID() string                             { return f.id }
func (f *fakeProxy) Type() string                           { return NOOP }
func (f *fakeProxy) Router() x.Router                       { return &GWNoVia{} }
func (f *fakeProxy) Client() x.Client                       { return newProxyClient(f) }
func (f *fakeProxy) onNotOK() (bool, bool)                  { return false, true }
func (f *fakeProxy) OnProtoChange(LinkProps) (string, bool) { return "", false }
func (f *fakeProxy) Hop(*core.WeakRef[Proxy], bool) error   { return nil }
func (f *fakeProxy) Status() int32                          { return TOK }
func (f *fakeProxy) GetAddr() string                        { return "" }
func (f *fakeProxy) setSince(int64)                         {}
func (f *fakeProxy) DNS() string                            { return "" }
func (f *fakeProxy) Ping() bool                             { return true }
func (f *fakeProxy) Pause() bool                            { return false }
func (f *fakeProxy) Resume() bool                           { return false }
func (f *fakeProxy) Stop() error                            { return nil }
func (f *fakeProxy) Refresh() error                         { return nil }

func restoreDefaultURLs(t *testing.T) func() {
	prevWs := wsGeoURL
	prevIPinfo := ipinfoURL
	prevTrace, prevWarp := traceURL, warpURL
	prevV4, prevV6 := mullvadV4URL, mullvadV6URL
	wsGeoURL = defaultWsGeoURL
	ipinfoURL = defaultIPinfoURL
	traceURL, warpURL = defaultTraceURL, defaultWarpURL
	mullvadV4URL, mullvadV6URL = defaultMullvadV4URL, defaultMullvadV6URL
	return func() {
		wsGeoURL = prevWs
		ipinfoURL = prevIPinfo
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
	handler.HandleFunc("/GeoGreet", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"geo":{"ip":"1.2.3.4","country_code":"US","city_name":"Dallas","isp":"Example Org","lat":"32.8","long":"-96.8"}},"errorCode":0}`))
	})
	handler.HandleFunc("/ip", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ip":"1.2.3.4","asn":"AS55824","as_name":"NKN Core Network","as_domain":"nkn.gov.in","country_code":"IN","country":"India","continent_code":"AS","continent":"Asia"}`))
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

func TestProxyClientWindscribe(t *testing.T) {
	srv := newIPv4Server(t)

	prevWs := wsGeoURL
	wsGeoURL = srv.URL + "/GeoGreet"
	defer func() { wsGeoURL = prevWs }()

	p := &fakeProxy{id: "test-ws"}
	meta, err := newProxyClient(p).IP4()
	if err != nil {
		t.Fatalf("windscribe err: %v", err)
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
	if meta.ProviderURL != wsGeoURL {
		t.Fatalf("provider mismatch: %v", meta.ProviderURL)
	}
}

func TestProxyClientIPinfo(t *testing.T) {
	srv := newIPv4Server(t)

	prevIPinfo := ipinfoURL
	ipinfoURL = srv.URL + "/ip"
	skipWsForTesting = true
	defer func() {
		skipWsForTesting = false
		ipinfoURL = prevIPinfo
	}()

	p := &fakeProxy{id: "test-ipinfo"}
	meta, err := newProxyClient(p).IP4()
	if err != nil {
		t.Fatalf("ipinfo err: %v", err)
	}
	if meta.IP != "1.2.3.4" {
		t.Fatalf("ip mismatch: %v", meta.IP)
	}
	if meta.CC != "IN" {
		t.Fatalf("cc mismatch: %v", meta.CC)
	}
	if meta.ASN != "AS55824" {
		t.Fatalf("asn mismatch: %v", meta.ASN)
	}
	if meta.ASNOrg != "NKN Core Network" {
		t.Fatalf("asn org mismatch: %v", meta.ASNOrg)
	}
	if meta.ASNDom != "nkn.gov.in" {
		t.Fatalf("asn dom mismatch: %v", meta.ASNDom)
	}
	if meta.ProviderURL != ipinfoURL {
		t.Fatalf("provider mismatch: %v", meta.ProviderURL)
	}
}

func TestProxyClientIP4(t *testing.T) {
	srv := newIPv4Server(t)

	prevWs, prevIPinfo, prevTrace, prevMull := wsGeoURL, ipinfoURL, traceURL, mullvadV4URL
	skipWsForTesting = true
	skipIPinfoForTesting = true
	skipTraceForTesting = true
	wsGeoURL, ipinfoURL, traceURL, mullvadV4URL = srv.URL+"/GeoGreet", srv.URL+"/ip", srv.URL+"/cdn-cgi/trace", srv.URL+"/json"
	defer func() {
		skipWsForTesting = false
		skipIPinfoForTesting = false
		skipTraceForTesting = false
		wsGeoURL, ipinfoURL, traceURL, mullvadV4URL = prevWs, prevIPinfo, prevTrace, prevMull
	}()

	p := &fakeProxy{id: "test-ipv4"}
	meta, err := newProxyClient(p).IP4()
	if err != nil {
		t.Fatalf("ip4 err: %v", err)
	}

	if meta.IP != "1.2.3.4" {
		t.Fatalf("ip mismatch: %v", meta.IP)
	}
	if meta.CC != "US" {
		// TODO: For mullvadV4URL, short country code isn't in the response
		// t.Fatalf("cc mismatch: %v", meta.CC)
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

	prevWs, prevIPinfo, prevTrace, prevMull := wsGeoURL, ipinfoURL, traceURL, mullvadV6URL
	skipWsForTesting = true
	skipIPinfoForTesting = true
	skipTraceForTesting = true
	wsGeoURL, ipinfoURL, traceURL, mullvadV6URL = srv.URL+"/GeoGreet", srv.URL+"/ip", srv.URL+"/cdn-cgi/trace", srv.URL+"/json"
	defer func() {
		skipWsForTesting = false
		skipIPinfoForTesting = false
		skipTraceForTesting = false
		wsGeoURL, ipinfoURL, traceURL, mullvadV6URL = prevWs, prevIPinfo, prevTrace, prevMull
	}()

	p := &fakeProxy{id: "test-ipv6"}
	meta, err := newProxyClient(p).IP6()
	if err != nil {
		t.Fatalf("ip6 err: %v", err)
	}

	if meta.IP != "1.2.3.4" {
		t.Fatalf("ip mismatch: %v", meta.IP)
	}
	if meta.CC != "US" {
		// TODO: For mullvadV6URL, short country code isn't in the response
		// t.Fatalf("cc mismatch: %v", meta.CC)
	}
	if meta.ProviderURL != mullvadV6URL {
		t.Fatalf("provider mismatch: %v", meta.ProviderURL)
	}
}

func TestProxyClientIP4Live(t *testing.T) {
	defer restoreDefaultURLs(t)()
	skipWsForTesting = false
	skipWarpForTesting = true
	skipTraceForTesting = true
	skipMullvadForTesting = true
	dialers.Mapper(ipmap.NewIPMapFor(systemMapper{}))

	p := &fakeProxy{id: "live-ipv4"}
	meta, err := newProxyClient(p).IP4()
	if err != nil {
		t.Fatalf("live ip4 err: %v", err)
	}
	t.Log(meta)

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
	skipWsForTesting = true
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

// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

const (
	defaultIPinfoURL    = "https://dl.rethinkdns.com/ip"
	defaultWsGeoURL     = "https://api.windscribe.net/GeoGreet"
	defaultTraceURL     = "https://sky.rethinkdns.com/cdn-cgi/trace"
	defaultWarpURL      = "https://redir.nile.workers.dev/p/warp"
	defaultMullvadV4URL = "https://ipv4.am.i.mullvad.net/json"
	defaultMullvadV6URL = "https://ipv6.am.i.mullvad.net/json"
	maxIPBodySize       = int64(128 * 1024)
	httpTimeout         = 10 * time.Second
)

// test hooks
var (
	ipinfoURL    = defaultIPinfoURL
	wsGeoURL     = defaultWsGeoURL
	traceURL     = defaultTraceURL
	warpURL      = defaultWarpURL
	mullvadV4URL = defaultMullvadV4URL
	mullvadV6URL = defaultMullvadV6URL

	skipWsForTesting      = false
	skipIPinfoForTesting  = false
	skipTraceForTesting   = false
	skipWarpForTesting    = false
	skipMullvadForTesting = false
)

var globalWsFakeBearer string

const (
	maxIpmetaLifetime = 1 * time.Hour
	minIpmetaLifetime = 12 * time.Minute
)

type ipmeta struct {
	id uint64
	*x.IPMetadata
}

var ipm = core.NewExpiringMap[string, *ipmeta](context.Background(), "ipn.pxc.ipm")

// ClearIPMeta clears the cached IP metadata for all proxies.
func ClearIPMeta() {
	ipm.Clear()
}

func getCachedIPMeta(p Proxy, network string) *x.IPMetadata {
	key := p.ID() + "/" + network + "/" + p.GetAddr()
	handle := p.DialerHandle()
	e, fresh := ipm.V(key)
	if !fresh || e == nil {
		return nil
	}
	if e.id != handle {
		ipm.Delete(key)
		return nil
	}
	return e.IPMetadata
}

func setCachedIPMeta(p Proxy, network string, meta *x.IPMetadata) {
	pid := p.ID()
	key := pid + "/" + network + "/" + p.GetAddr()
	until := maxIpmetaLifetime
	if local(pid) {
		// local proxies' dialerhandle never recreate (on network changes)
		// and so, we are aggressive for how long we'll cache their responses
		until = minIpmetaLifetime
	}
	ipm.K(key, &ipmeta{p.DialerHandle(), meta}, until)
}

type proxyClient struct {
	p Proxy
}

var _ x.Client = (*proxyClient)(nil)

func newProxyClient(p Proxy) x.Client {
	return &proxyClient{p: p}
}

// IP4 implements x.Client.
func (c *proxyClient) IP4() (*x.IPMetadata, error) {
	return fetchIPMetadata(c.p, "tcp4")
}

// IP6 implements x.Client.
func (c *proxyClient) IP6() (*x.IPMetadata, error) {
	return fetchIPMetadata(c.p, "tcp6")
}

func fetchIPMetadata(p Proxy, network string) (*x.IPMetadata, error) {
	if cached := getCachedIPMeta(p, network); cached != nil {
		return cached, nil
	}

	st := p.Status()
	if st != TOK && st != TKO {
		return nil, errNotActive
	}

	rt := p.Router()
	// "tcp" and "udp" are dual-stack
	is4 := network == "tcp4" || network == "udp4" || network == "ip4"
	is6 := network == "tcp6" || network == "udp6" || network == "ip6"
	is46 := network == "tcp" || network == "udp" || network == "ip"
	if !rt.IP4() && is4 {
		return nil, errProxyRoute
	}
	if !rt.IP6() && is6 {
		return nil, errProxyRoute
	}
	if !rt.IP4() && !rt.IP6() && is46 {
		return nil, errProxyRoute
	}

	meta := &x.IPMetadata{ID: idstr(p)}
	mullvadURL := mullvadV4URL
	if network == "tcp6" {
		mullvadURL = mullvadV6URL
	}

	if ipi, err0 := fetchIPinfo(p, network); err0 == nil {
		applyIPinfo(meta, ipi)
		meta.ProviderURL = ipinfoURL
	} else if ws, err1 := fetchWindscribe(p, network); err1 == nil {
		applyWindscribe(meta, ws)
		meta.ProviderURL = wsGeoURL
	} else if trace, err2 := fetchTrace(p, network); err2 == nil {
		applyTrace(meta, trace)
		meta.ProviderURL = traceURL
	} else if warp, err3 := fetchWarp(p, network); err3 == nil {
		applyWarp(meta, warp)
		meta.ProviderURL = warpURL
	} else if mull, err4 := fetchMullvad(p, network, mullvadURL); err4 == nil {
		applyMullvad(meta, mull)
		meta.ProviderURL = mullvadURL
	} else {
		perr := fmt.Errorf("proxy: client: %s %s lookup failed", idstr(p), network)
		return nil, core.JoinErr(perr, err0, err1, err2, err3, err4)
	}

	if len(meta.IP) <= 0 {
		return nil, fmt.Errorf("proxy: client: %s %s lookup failed", idstr(p), network)
	}

	setCachedIPMeta(p, network, meta)
	return meta, nil
}

// fakeBearer generates a fake Windscribe-shaped Bearer token.
// Format: <9-digit-id>:1:<unix-epoch>:<42-hex-sig1>:<42-hex-sig2>
func fakeBearer(change bool) string {
	if change || len(globalWsFakeBearer) == 0 {
		maxID := big.NewInt(900000000)
		n, err := rand.Int(rand.Reader, maxID)
		if err != nil {
			n = big.NewInt(21102401) // fallback
		}
		id := n.Int64() + 100000000 // ensure 9 digits

		sig := func() string {
			b := make([]byte, 21) // 21 bytes → 42 hex chars
			rand.Read(b)          //nolint:errcheck
			return hex.EncodeToString(b)
		}

		globalWsFakeBearer = fmt.Sprintf("%d:1:%d:%s:%s", id, time.Now().Unix(), sig(), sig())
	}
	return globalWsFakeBearer
}

//	{
//		"data": {
//			"geo": {
//				"ip": "14.139.180.67",
//				"country_name": "India",
//				"country_code": "IN",
//				"city_name": "Coimbatore",
//				"isp": "NKN Core Network",
//				"lat": "11.01020",
//				"long": "76.97010"
//			}
//		}
//	}
type wsGeoInner struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CityName    string `json:"city_name"`
	ISP         string `json:"isp"`
	Lat         string `json:"lat"`
	Long        string `json:"long"`
}

type wsResp struct {
	Data struct {
		Geo wsGeoInner `json:"geo"`
	} `json:"data"`
	ErrorCode int `json:"errorCode"`
}

func fetchWindscribe(p Proxy, network string) (*wsGeoInner, error) {
	if skipWsForTesting {
		return nil, errors.New("testing: windscribe skipped")
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wsGeoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+fakeBearer(false))
	req.Header.Set("Origin", "https://windscribe.net")
	req.Header.Set("Referer", "https://windscribe.net")

	log.VV("proxy: client: %s fetching windscribe via %s...", idstr(p), network)

	client := httpClient(p, network, httpTimeout)
	resp, err := client.Do(req)
	if resp == nil {
		return nil, core.OneErr(err, errors.New("proxy: client: windscribe nil response"))
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		defer fakeBearer(true)
		return nil, fmt.Errorf("proxy: client: windscribe status %s / err? %v", resp.Status, err)
	}
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIPBodySize))
	if err != nil {
		return nil, err
	}

	var ws wsResp
	if err := json.Unmarshal(data, &ws); err != nil {
		return nil, err
	}
	if ws.ErrorCode != 0 {
		return nil, fmt.Errorf("proxy: client: windscribe error %d", ws.ErrorCode)
	}
	if ws.Data.Geo.IP == "" {
		return nil, errors.New("proxy: client: empty windscribe response")
	}

	return &ws.Data.Geo, nil
}

func applyWindscribe(meta *x.IPMetadata, geo *wsGeoInner) {
	if geo.IP != "" {
		meta.IP = geo.IP
	}
	if geo.CountryCode != "" {
		meta.CC = strings.ToUpper(geo.CountryCode)
	}
	if geo.CityName != "" {
		meta.City = geo.CityName
	}
	if geo.ISP != "" {
		meta.ASNOrg = geo.ISP
	}
	if lat, err := strconv.ParseFloat(strings.TrimSpace(geo.Lat), 64); err == nil {
		meta.Lat = lat
	}
	if lon, err := strconv.ParseFloat(strings.TrimSpace(geo.Long), 64); err == nil {
		meta.Lon = lon
	}
}

//	{
//		"ip": "14.139.180.67",
//		"asn": "AS55824",
//		"as_name": "NKN Core Network",
//		"as_domain": "nkn.gov.in",
//		"country_code": "IN",
//		"country": "India",
//		"continent_code": "AS",
//		"continent": "Asia"
//	}
type ipinfoResp struct {
	IP          string `json:"ip"`
	ASN         string `json:"asn"`
	ASName      string `json:"as_name"`
	ASDomain    string `json:"as_domain"`
	CountryCode string `json:"country_code"`
}

func fetchIPinfo(p Proxy, network string) (*ipinfoResp, error) {
	if skipIPinfoForTesting {
		return nil, errors.New("testing: ipinfo skipped")
	}

	body, err := fetch(p, network, ipinfoURL)
	if err != nil {
		return nil, err
	}

	var resp ipinfoResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	if resp.IP == "" {
		return nil, errors.New("proxy: client: empty ipinfo response")
	}

	return &resp, nil
}

func applyIPinfo(meta *x.IPMetadata, resp *ipinfoResp) {
	if resp.IP != "" {
		meta.IP = resp.IP
	}
	if resp.ASN != "" {
		meta.ASN = resp.ASN
	}
	if resp.ASName != "" {
		meta.ASNOrg = resp.ASName
	}
	if resp.ASDomain != "" {
		meta.ASNDom = resp.ASDomain
	}
	if resp.CountryCode != "" {
		meta.CC = strings.ToUpper(resp.CountryCode)
	}
}

// fetchTrace fetches the Cloudflare trace data via the given proxy.
// fl=765f119
// h=sky.rethinkdns.com
// ip=dead:beef::dead:beef
// ts=1766262434
// visit_scheme=https
// uag=.../...
// colo=GRU
// sliver=none
// http=http/2
// loc=BR
// tls=TLSv1.3
// sni=plaintext
// warp=off
// gateway=off
// rbi=off
// kex=X25519
func fetchTrace(p Proxy, network string) (map[string]string, error) {
	if skipTraceForTesting {
		return nil, errors.New("testing: trace skipped")
	}

	body, err := fetch(p, network, traceURL)
	if err != nil {
		return nil, err
	}

	kv := make(map[string]string)
	for line := range strings.SplitSeq(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		kv[parts[0]] = parts[1]
	}

	if len(kv) == 0 {
		return nil, errors.New("proxy: client: empty trace response")
	}

	return kv, nil
}

//	{
//	 	"vcode":"...",
//	 	"minvcode":"...",
//		"cansell":false,
//		"ip":"dead:beef::dead:beef",
//		"country":"br",
//		"asorg":"NETWORKS",
//		"city":"São Paulo",
//		"colo":"BR",
//		"region":"São Paulo State",
//		"postalcode":"01000-000",
//		"addrs":[],
//		"status":"ok",
//		"pubkey": {jwk}
//	}
type warpResp struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Region    string  `json:"region"`
	ASNOrg    string  `json:"asorg"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

func fetchWarp(p Proxy, network string) (*warpResp, error) {
	if skipWarpForTesting {
		return nil, errors.New("testing: warp skipped")
	}

	body, err := fetch(p, network, warpURL)
	if err != nil {
		return nil, err
	}

	var resp warpResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	if resp.IP == "" {
		return nil, errors.New("proxy: client: empty warp response")
	}

	return &resp, nil
}

//	{
//		"ip":"w.x.y.z",
//		"country":"Brazil",
//		"city":"São Paulo",
//		"longitude":-46.6333,
//		"latitude":-23.5505,
//		"mullvad_exit_ip":false,
//		"blacklisted":{"blacklisted":false,"results":[]},
//		"organization":"Example Org"
//	}
type mullvadResp struct {
	IP           string  `json:"ip"`
	Country      string  `json:"country"`
	City         string  `json:"city"`
	Longitude    float64 `json:"longitude"`
	Latitude     float64 `json:"latitude"`
	Organization string  `json:"organization"`
}

func fetchMullvad(p Proxy, network, url string) (*mullvadResp, error) {
	if skipMullvadForTesting {
		return nil, errors.New("testing: mullvad skipped")
	}

	body, err := fetch(p, network, url)
	if err != nil {
		return nil, err
	}

	var resp mullvadResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	if resp.IP == "" {
		return nil, errors.New("proxy: client: empty mullvad response")
	}

	return &resp, nil
}

func applyTrace(meta *x.IPMetadata, kv map[string]string) {
	if ip, ok := kv["ip"]; ok {
		meta.IP = ip
	}
	if cc, ok := kv["loc"]; ok {
		meta.CC = strings.ToUpper(cc)
	}
}

func applyWarp(meta *x.IPMetadata, resp *warpResp) {
	meta.IP = resp.IP
	if resp.Country != "" {
		meta.CC = strings.ToUpper(resp.Country)
	}
	if resp.City != "" {
		meta.City = resp.City
	} else if resp.Region != "" {
		meta.City = resp.Region
	}
	if resp.ASNOrg != "" {
		meta.ASNOrg = resp.ASNOrg
	}
	if resp.Latitude != 0 {
		meta.Lat = resp.Latitude
	}
	if resp.Longitude != 0 {
		meta.Lon = resp.Longitude
	}
}

func applyMullvad(meta *x.IPMetadata, resp *mullvadResp) {
	if resp.IP != "" {
		meta.IP = resp.IP
	}
	if resp.Country != "" && meta.CC == "" {
		// TODO: resp.Country isn't country code
		// meta.CC = resp.Country
	}
	if resp.City != "" {
		meta.City = resp.City
	}
	if resp.Organization != "" {
		meta.ASNOrg = resp.Organization
	}
	if resp.Latitude != 0 {
		meta.Lat = resp.Latitude
	}
	if resp.Longitude != 0 {
		meta.Lon = resp.Longitude
	}
}

func fetch(p Proxy, network, rawurl string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}

	log.VV("proxy: client: %s fetching %s via %s...", idstr(p), rawurl, network)

	// TODO: pool clients
	client := httpClient(p, network, httpTimeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("proxy: client: ip lookup nil response")
	}
	defer core.Close(resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("proxy: client: ip lookup %s: status %s", rawurl, resp.Status)
	}

	log.VV("proxy: client: %s fetched %s via %s with status %s; reading body...", idstr(p), rawurl, network, resp.Status)

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIPBodySize))
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Exported for testing only.
func HttpClient(p Proxy, network string, timeout time.Duration) *http.Client {
	return httpClient(p, network, timeout)
}

func httpClient(p Proxy, network string, httpTimeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}

				if port == "" {
					return nil, log.EE("proxy: client: no port in %q", addr)
				}

				on, err := strconv.Atoi(port)
				if err != nil || on <= 0 {
					return nil, log.EE("proxy: client: invalid port %q in %q", port, addr)
				}

				// use preferred when proxy does not have dns
				dnsid := x.Preferred
				if hasDNS := len(p.DNS()) > 0; hasDNS {
					dnsid = p.ID()
				}

				ips, err := dialers.Resolve(host, dnsid)
				if err != nil {
					if settings.DefaultDNSAsFallback.Load() {
						log.D("proxy: client: %s on %s resolve %s err %s: %v; using Default",
							idstr(p), network, dnsid, host, err)
						ips = dialers.For(host)
					} else {
						log.E("proxy: client: %s on %s resolve %s err %s: %v",
							idstr(p), network, dnsid, host, err)
						return nil, err
					}
				}

				filtered := make([]netip.Addr, 0, len(ips))
				for _, ip := range ips {
					if (network == "udp" || network == "udp6" || network == "tcp" || network == "tcp4") && ip.Is4() {
						filtered = append(filtered, ip)
					}
					if (network == "udp" || network == "udp6" || network == "tcp" || network == "tcp6") && ip.Is6() {
						filtered = append(filtered, ip)
					}
				}

				if len(filtered) == 0 {
					return nil, errNoSuitableAddress
				}

				log.VV("proxy: client: %s resolved %s to %v on port %d for %s",
					idstr(p), host, filtered, on, network)

				var lastErr error
				for _, ip := range filtered {
					dest := netip.AddrPortFrom(ip, uint16(on)).String()
					if conn, err := p.Dial(network, dest); err == nil {
						log.VV("proxy: client: %s dialed %s @ %s on %s",
							idstr(p), host, dest, network)
						return conn, nil
					} else {
						log.E("proxy: client: %s failed to dial %s @ %s on %s: %v",
							idstr(p), host, dest, network, err)
						lastErr = err
					}
				}

				if lastErr == nil {
					lastErr = errNoSuitableAddress
				}
				return nil, lastErr
			},
			TLSHandshakeTimeout:   httpTimeout / 2,
			ResponseHeaderTimeout: httpTimeout - 2,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     true,
		},
	}
}

func (h *base) Client() x.Client    { return newProxyClient(h) }
func (h *exit) Client() x.Client    { return newProxyClient(h) }
func (h *exit64) Client() x.Client  { return newProxyClient(h) }
func (h *auto) Client() x.Client    { return newProxyClient(h) }
func (h *socks5) Client() x.Client  { return newProxyClient(h) }
func (h *http1) Client() x.Client   { return newProxyClient(h) }
func (h *wgproxy) Client() x.Client { return newProxyClient(h) }
func (h *pipws) Client() x.Client   { return newProxyClient(h) }
func (h *piph2) Client() x.Client   { return newProxyClient(h) }

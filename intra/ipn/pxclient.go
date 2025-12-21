// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
)

const (
	defaultTraceURL     = "https://sky.rethinkdns.com/cdn-cgi/trace"
	defaultWarpURL      = "https://redir.nile.workers.dev/p/warp"
	defaultMullvadV4URL = "https://ipv4.am.i.mullvad.net/json"
	defaultMullvadV6URL = "https://ipv6.am.i.mullvad.net/json"
	maxIPBodySize       = int64(128 * 1024)
	httpTimeout         = 10 * time.Second
)

// test hooks
var (
	traceURL     = defaultTraceURL
	warpURL      = defaultWarpURL
	mullvadV4URL = defaultMullvadV4URL
	mullvadV6URL = defaultMullvadV6URL

	skipTraceForTesting   = false
	skipWarpForTesting    = false
	skipMullvadForTesting = false
)

type proxyClient struct {
	p Proxy
}

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
	meta := &x.IPMetadata{ID: idstr(p)}
	mullvadURL := mullvadV4URL
	if network == "tcp6" {
		mullvadURL = mullvadV6URL
	}

	if trace, err1 := fetchTrace(p, network); err1 == nil {
		applyTrace(meta, trace)
		meta.ProviderURL = traceURL
	} else if warp, err2 := fetchWarp(p, network); err2 == nil {
		applyWarp(meta, warp)
		meta.ProviderURL = warpURL
	} else if mull, err3 := fetchMullvad(p, network, mullvadURL); err3 == nil {
		applyMullvad(meta, mull)
		meta.ProviderURL = mullvadURL
	} else {
		perr := fmt.Errorf("proxy: %s ip lookup failed", idstr(p))
		return nil, core.JoinErr(perr, err1, err2, err3)
	}

	if len(meta.IP) <= 0 {
		return nil, fmt.Errorf("proxy: %s ip lookup failed", idstr(p))
	}

	return meta, nil
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
		return nil, errors.New("empty trace response")
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
		return nil, errors.New("empty warp response")
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
		return nil, errors.New("empty mullvad response")
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
		meta.CC = resp.Country
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
	parsed, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	client := httpClient(p, network, parsed)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("ip lookup %s: status %s", rawurl, resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIPBodySize))
	if err != nil {
		return nil, err
	}

	return data, nil
}

func httpClient(p Proxy, network string, u *url.URL) *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}

				if port == "" {
					switch {
					case u.Port() != "":
						port = u.Port()
					case u.Scheme == "https":
						port = "443"
					default:
						port = "80"
					}
				}

				on, _ := strconv.Atoi(port)
				if on <= 0 {
					if u.Scheme == "https" {
						on = 443
					} else {
						on = 80
					}
				}

				ips := dialers.For(host)
				filtered := make([]netip.Addr, 0, len(ips))
				for _, ip := range ips {
					if network == "tcp4" && ip.Is4() {
						filtered = append(filtered, ip)
					}
					if network == "tcp6" && ip.Is6() {
						filtered = append(filtered, ip)
					}
				}

				if len(filtered) == 0 {
					return nil, errNoSuitableAddress
				}

				var lastErr error
				for _, ip := range filtered {
					dest := netip.AddrPortFrom(ip, uint16(on)).String()
					if conn, err := p.Dial(network, dest); err == nil {
						return conn, nil
					} else {
						lastErr = err
					}
				}

				if lastErr == nil {
					lastErr = errNoSuitableAddress
				}
				return nil, lastErr
			},
			TLSHandshakeTimeout:   httpTimeout,
			ResponseHeaderTimeout: httpTimeout,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     true,
		},
	}
}

// Client implementations for proxies that previously lacked x.Client.
func (h *base) Client() x.Client    { return newProxyClient(h) }
func (h *exit) Client() x.Client    { return newProxyClient(h) }
func (h *exit64) Client() x.Client  { return newProxyClient(h) }
func (h *auto) Client() x.Client    { return newProxyClient(h) }
func (h *socks5) Client() x.Client  { return newProxyClient(h) }
func (h *http1) Client() x.Client   { return newProxyClient(h) }
func (h *wgproxy) Client() x.Client { return newProxyClient(h) }
func (h *seproxy) Client() x.Client { return newProxyClient(h) }
func (t *pipws) Client() x.Client   { return newProxyClient(t) }
func (t *piph2) Client() x.Client   { return newProxyClient(t) }

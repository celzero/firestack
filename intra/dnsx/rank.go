// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

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
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
)

const (
	// rankHost serves domain reputation (top 1M / popular ranks) lookups.
	rankHost = "dl.rethinkdns.com"
	// rankDomURL is the rank endpoint; the lowercased domain name is appended.
	rankDomURL = "https://" + rankHost + "/dom/"
	// rankStaleAfter marks client-cached ranks older than this for a refetch.
	rankStaleAfter = 30 * 24 * time.Hour
	// rankConnTimeout bounds tcp dial for rank lookups.
	rankConnTimeout = 3 * time.Second
	// rankHdrTimeout bounds waiting for rank response headers.
	rankHdrTimeout = 5 * time.Second
	// rankTotalTimeout bounds the entire rank lookup.
	rankTotalTimeout = 9 * time.Second
	// rankFetchTimeout bounds resolve + dial + get for a rank lookup.
	rankFetchTimeout = 12 * time.Second
	// rankMaxBody caps the rank response body (in bytes).
	rankMaxBody = 32 * 1024
)

var errNoRankConn = errors.New("dns: no rank conn")

// rankReply is the wire format of GET https://dl.rethinkdns.com/dom/<domain>.
// Success: {"domain":"...","rank":113260,"rankbig":113260,"colo":"LHR","success":true}.
// Rank is -1 when the domain is not in the top 1M (rankbig likewise for popular ranks).
// Failure: {"domain":"...","colo":"","success":false,"errors":["..."]}.
type rankReply struct {
	Domain  string   `json:"domain"`
	Rank    int32    `json:"rank"`
	RankBig int32    `json:"rankbig"`
	Colo    string   `json:"colo"`
	Success bool     `json:"success"`
	Errors  []string `json:"errors"`
}

// skipRank reports whether rank fetch & enforcement must be skipped for qname.
// Ranks are reported as zero and the query is never rank-blocked.
func (r *resolver) skipRank(qname string) bool {
	if len(qname) <= 0 || qname == invalidQname {
		return true
	}
	if qname == rankHost { // avoid recursion
		return true
	}
	if _, err := netip.ParseAddr(qname); err == nil { // ips have no ranks
		return true
	}
	return isUndelegatedDomain(r.LocalDomains(), qname)
}

// skipRankBlock reports whether rank enforcement must be skipped: ranks are
// still reported, but the query is never rank-blocked.
func skipRankBlock(pref *x.DNSOpts, preset []netip.Addr, t, t2 Transport) bool {
	if pref != nil && pref.NOBLOCK {
		return true
	}
	if len(preset) > 0 { // IPCSV answers bypass blocks
		return true
	}
	return skipBlock(t, t2) // BlockFree / Alg transports
}

// rankStale reports whether client-cached ranks from dob (unix millis) must be refetched.
func rankStale(dob int64) bool {
	if dob <= 0 {
		return true
	}
	return time.Since(time.UnixMilli(dob)) > rankStaleAfter
}

// rankMeets reports whether v satisfies threshold th (th <= 0 disables the check).
// Unknown (0) and unranked (-ve) values never meet a positive threshold.
func rankMeets(v, th int32) bool {
	if th <= 0 {
		return true
	}
	return v > 0 && v <= th
}

// rankres is the outcome of a rank fetch.
type rankres struct {
	rank, rankbig int32
	errs          []string
}

// resolveRank determines ranks for qname from dom hints, fetching from the
// rank endpoint when needed. It returns the ranks, csv rank errors, whether
// the query must be blocked, and why.
func (r *resolver) resolveRank(domopts *x.DomainOpts, qname string) (rank, rankbig int32, rankerr string, block bool, reason string) {
	if domopts == nil {
		return 0, 0, "", false, ""
	}
	th, thbig := domopts.RankThreshold, domopts.RankBigThreshold
	if th <= 0 && thbig <= 0 {
		return domopts.Rank, domopts.RankBig, "", false, ""
	}
	if r.skipRank(qname) {
		return 0, 0, "", false, ""
	}
	rank, rankbig = domopts.Rank, domopts.RankBig
	if (rank == 0 && rankbig == 0) || rankStale(domopts.RankDobUnixMs) {
		fr, completed := core.Grx("rank.fetch."+qname, func(context.Context) (rankres, error) {
			a, b, errs := r.fetchRank(domopts.FID, qname)
			return rankres{a, b, errs}, nil
		}, rankFetchTimeout)
		if !completed {
			rankerr = "rank fetch timeout"
			return 0, 0, rankerr, true, "rank lookup failed: " + rankerr
		}
		if len(fr.errs) > 0 {
			rankerr = strings.Join(fr.errs, ",")
			// fail closed: ranks stay 0 (unknown)
			return 0, 0, rankerr, true, "rank lookup failed: " + rankerr
		}
		rank, rankbig = fr.rank, fr.rankbig
	}
	if !rankMeets(rank, th) {
		return rank, rankbig, rankerr, true,
			fmt.Sprintf("rank %d not within threshold %d", rank, th)
	}
	if !rankMeets(rankbig, thbig) {
		return rank, rankbig, rankerr, true,
			fmt.Sprintf("rankbig %d not within threshold %d", rankbig, thbig)
	}
	return rank, rankbig, rankerr, false, ""
}

// makeRankClient returns an http client dialing over the base proxy for
// rank lookups. Name resolution and retries are handled by the dialers
// (see localDialStrat in intra/ipn). Panics if no base proxy is found.
func makeRankClient(pxr ipn.ProxyProvider) *http.Client {
	p, perr := pxr.ProxyFor(x.Base)
	if p == nil || core.IsNil(p) {
		panic("makeRankClient: no base proxy: " + perr.Error())
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network string, addr string) (net.Conn, error) {
				return p.Dial(network, addr)
			},
			TLSHandshakeTimeout:   rankConnTimeout,
			ResponseHeaderTimeout: rankHdrTimeout,
			ForceAttemptHTTP2:     true,
		},
		Timeout: rankTotalTimeout,
	}
}

// fetchRank GETs ranks for qname from the rank endpoint over the base network.
// It returns the fetched ranks, or the errors encountered.
func (r *resolver) fetchRank(fid string, qname string) (int32, int32, []string) {
	client := r.rankclient // built once via NewResolver; never reassigned

	endpoint := rankDomURL + url.PathEscape(strings.ToLower(qname))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)

	resp, err := client.Do(req)
	if resp == nil && err == nil {
		err = errNoRankConn
	}
	if err != nil {
		return 0, 0, []string{"rank get: " + err.Error()}
	}
	defer core.Close(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, 0, []string{"rank http: " + strconv.Itoa(resp.StatusCode)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, rankMaxBody))
	if err != nil {
		return 0, 0, []string{"rank read: " + err.Error()}
	}

	var rr rankReply
	if err := json.Unmarshal(body, &rr); err != nil {
		return 0, 0, []string{"rank json: " + err.Error()}
	}

	if !rr.Success {
		if len(rr.Errors) <= 0 {
			rr.Errors = []string{"rank lookup failed"}
		}
		return 0, 0, rr.Errors
	}

	if log.Verbose {
		log.V("rank: %s: %s => %d/%d", fid, qname, rr.Rank, rr.RankBig)
	}
	return rr.Rank, rr.RankBig, nil
}

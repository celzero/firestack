// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package doh

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

// adopted from: github.com/folbricht/routedns/pull/118
// and: github.com/cloudflare/odoh-client/blob/4762219808/commands/request.go

// constants from: github.com/cloudflare/odoh-client-go/blob/8d45d054d3/commands/common.go#L4
const odohmimetype = "application/oblivious-dns-message"
const odohconfigdns = "https://1.1.1.1/dns-query"
const odohtargetscheme = "https"
const odohconfigwkpath = "/.well-known/odohconfigs"
const odohtargetpath = "/dns-query"
const odohproxypath = "/proxy" // dns-query in latest spec
const odohttlsec = 3600        // 1hr

var (
	errMissingOdohQuery       = errors.New("no odoh request")
	errMissingOdohCfgQuery    = errors.New("no odoh config request")
	errMissingOdohCfgResponse = errors.New("no odoh config response")
	errZeroOdohCfgs           = errors.New("no odoh configs found")
)

// targets:  github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-servers.md
// endpoints:  github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md
func (d *transport) doOdoh(pid string, q *dns.Msg) (res *dns.Msg, elapsed time.Duration, qerr *dnsx.QueryError) {
	var ans []byte
	viaproxy := len(d.odohproxy) > 0

	odohmsg, odohctx, err := d.buildTargetQuery(q)
	if err != nil {
		log.W("odoh: build target query err: %v", err)
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	oq := odohmsg.Marshal()
	req, err := d.asOdohRequest(oq)
	if err != nil {
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	ans, _, elapsed, qerr = d.do(pid, req)
	log.V("odoh: send; proxy? %t, elapsed: %s; err? %v", viaproxy, elapsed, qerr)
	if qerr != nil {
		// datatracker.ietf.org/doc/rfc9230 section 4.3 and section 7
		// 401 authorization error on hpke failure
		// 400 bad request on padding or other failures
		// these are "transport errors", in which case we should retry
		// but for now, invalidate cached odoh config, if any
		if qerr.Status() == dnsx.ClientError {
			d.omu.Lock()
			d.odohConfig = nil
			d.odohConfigExpiry = time.Now()
			d.omu.Unlock()
		}
		res = xdns.Servfail(q) // servfail on the original query
		return
	}

	oans, err := odoh.UnmarshalDNSMessage(ans)
	if err != nil {
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}

	ans, err = odohctx.OpenAnswer(oans)
	if err != nil {
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	log.V("odoh: success; res: %d", len(ans))
	res = new(dns.Msg) // unpack into a new msg
	if err = res.Unpack(ans); err != nil {
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}
	return
}

func (d *transport) asOdohRequest(q []byte) (req *http.Request, err error) {
	viaproxy := len(d.odohproxy) > 0
	// ref: github.com/cloudflare/odoh-client-go/blob/8d45d054d3/commands/request.go#L53
	if viaproxy {
		req, err = http.NewRequest(http.MethodPost, d.odohproxy, bytes.NewBuffer(q))
		if err != nil {
			return
		}
		if req == nil || req.URL == nil {
			err = errMissingOdohQuery
			return
		}
		query := req.URL.Query()
		if query == nil {
			query = make(url.Values)
		}
		query.Add("targethost", d.odohtargetname)
		query.Add("targetpath", d.odohtargetpath)
		req.URL.RawQuery = query.Encode()
	} else {
		req, err = http.NewRequest(http.MethodPost, d.odohTargetUrl(), bytes.NewBuffer(q))
		if err != nil {
			return
		}
	}
	req.Header.Set("user-agent", "")
	req.Header.Set("content-type", odohmimetype)
	req.Header.Add("accept", odohmimetype)
	return
}

func (d *transport) buildTargetQuery(msg *dns.Msg) (m odoh.ObliviousDNSMessage, ctx odoh.QueryContext, err error) {
	ocfg, err := d.fetchTargetConfig()
	if err != nil {
		return
	}
	if ocfg == nil {
		err = errZeroOdohCfgs
		return
	}
	q, err := msg.Pack()
	if err != nil {
		return
	}

	key := ocfg.Contents
	pad := computePaddingSize(msg.Len(), PaddingBlockSize)
	oq := odoh.CreateObliviousDNSQuery(q, uint16(pad))
	log.V("odoh: build-target: odoh qlen %d", len(oq.DnsMessage)+len(oq.Padding))
	return key.EncryptQuery(oq)
}

// Get the current (cached) target config or refresh it if expired.
func (d *transport) fetchTargetConfig() (cfg *odoh.ObliviousDoHConfig, err error) {
	d.omu.RLock()
	ok1 := d.odohConfig != nil
	ok2 := time.Now().Before(d.odohConfigExpiry)
	d.omu.RUnlock()

	if ok1 && ok2 { // return cached config
		log.V("odoh: fetch-target: using cached config for %s", d.odohtargetname)
		return d.odohConfig, nil
	}

	var exp time.Time
	cfg, exp, err = d.refresh()
	d.omu.Lock()
	d.odohConfig, d.odohConfigExpiry = cfg, exp // may be nil, 0 on error
	d.omu.Unlock()

	log.V("odoh: fetch-target: using refereshed config for %s; expiring: %s", d.odohtargetname, exp)
	return
}

func (d *transport) refresh() (cfg *odoh.ObliviousDoHConfig, exp time.Time, err error) {
	first := d.refreshTargetKeyDNS
	second := d.refreshTargetKeyWellKnown
	if d.preferWK {
		first = d.refreshTargetKeyWellKnown
		second = d.refreshTargetKeyDNS
	}

	if cfg, exp, err = first(); err != nil {
		d.preferWK = !d.preferWK
		if cfg, exp, err = second(); err != nil {
			return
		}
	}
	log.V("odoh: fetch-target: %s; expiring: %s", d.odohtargetname, exp)
	return
}

func (d *transport) refreshTargetKeyWellKnown() (ocfg *odoh.ObliviousDoHConfig, exp time.Time, err error) {
	var req *http.Request
	var resp *http.Response

	req, err = http.NewRequest(http.MethodGet, d.odohConfigUrl(), nil)
	if err != nil {
		return
	}
	if req == nil {
		err = errMissingOdohCfgQuery
		return
	}
	resp, err = d.wkclient.Do(req)
	if err != nil {
		return
	}
	if resp == nil || resp.Body == nil {
		err = errMissingOdohCfgResponse
		return
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	ocfgs, err := odoh.UnmarshalObliviousDoHConfigs(bodyBytes)
	if err != nil {
		log.W("odoh: refresh-target-wk: unmarshal config err: %v", err)
		return
	} else if len(ocfgs.Configs) <= 0 {
		log.W("odoh: refresh-target-wk: no configs found")
		err = errZeroOdohCfgs
		return
	}
	ocfg = &ocfgs.Configs[0]
	exp = time.Now().Add(odohttlsec * time.Second)
	log.V("odoh: refresh-target-wk: %s; %v; expiring: %s", d.odohtargetname, ocfg, exp)
	return
}

func (d *transport) refreshTargetKeyDNS() (ocfg *odoh.ObliviousDoHConfig, exp time.Time, err error) {
	cmsg := new(dns.Msg)
	cmsg.SetQuestion(dns.Fqdn(d.odohtargetname), dns.TypeHTTPS)

	// doh query for odoh-config is sent to odohconfigdns
	req, err := d.asDohRequest(cmsg)
	if err != nil {
		return
	}
	cres, _, t1, qerr := d.send(dnsx.NetNoProxy, req)

	log.D("odoh: refresh-target: %s; elapsed: %dms; err? %v", d.odohtargetname, t1.Milliseconds(), qerr)
	if qerr != nil {
		err = qerr.Unwrap()
		return
	}

	if cres == nil || !xdns.HasAnyAnswer(cres) {
		log.W("odoh: refresh-target: no config ans")
		err = errMissingOdohCfgResponse
		return
	}

	for _, rec := range cres.Answer {
		https, ok := rec.(*dns.HTTPS)
		if !ok {
			log.V("odoh: refresh-target: config not a https record; next")
			continue
		}
		ttlsec := time.Duration(rec.Header().Ttl) * time.Second
		for _, kv := range https.Value {
			// up until draft-06, the key was 0x8001
			if kv.Key() != 32769 {
				log.D("odoh: refresh-target: unexpected https record key; next")
				continue
			}
			var ocfgs odoh.ObliviousDoHConfigs
			if svcblocal, ok := kv.(*dns.SVCBLocal); ok {
				ocfgs, err = odoh.UnmarshalObliviousDoHConfigs(svcblocal.Data)
				if err != nil {
					log.W("odoh: refresh-target: unmarshal config err: %v", err)
					return
				} else if len(ocfgs.Configs) <= 0 {
					log.W("odoh: refresh-target: no configs found")
					err = errZeroOdohCfgs
					return
				}
				ocfg = &ocfgs.Configs[0]
				exp = time.Now().Add(ttlsec)
				log.V("odoh: refresh-target: %s; %v; expiring: %s", d.odohtargetname, ocfg, exp)
				return
			} else {
				log.D("odoh: refresh-target: not a svcblocal value; next")
			}
		}
	}

	log.W("odoh: refresh-target: no config in https/svcb %d", len(cres.Answer))
	log.V("odoh: refresh-target: dns ans %v", cres.Answer)
	err = errMissingOdohCfgResponse
	return
}

func (d *transport) odohTargetUrl() string {
	u := new(url.URL)
	u.Scheme = odohtargetscheme
	u.Path = d.odohtargetpath
	u.Host = d.odohtargetname
	return u.String()
}

func (d *transport) odohConfigUrl() string {
	u := new(url.URL)
	u.Scheme = odohtargetscheme
	u.Path = odohconfigwkpath
	u.Host = d.odohtargetname
	return u.String()
}

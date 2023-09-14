// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package doh

import (
	"errors"
	"net/http"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

// adopted from: github.com/folbricht/routedns/pull/118

const odohmimetype = "application/oblivious-dns-message"

var errNoOdohCfgResponse = errors.New("no odoh config response")
var errZeroOdohCfgs = errors.New("no odoh configs found")

// targets:  github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-servers.md
// endpoints:  github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md
func (d *transport) doOdoh(q []byte) (res []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	odohmsg, odohctx, err := d.buildTargetQuery(q)
	if err != nil {
		log.W("odoh: build target query err: %v", err)
		qerr = dnsx.NewBadQueryError(err)
		return
	}

	oq := odohmsg.Marshal()
	req, err := d.asDohRequest(oq)
	if err != nil {
		qerr = dnsx.NewInternalQueryError(err)
		return
	}
	d.customizeForOdoh(req)

	res, _, elapsed, qerr = d.send(req)
	log.V("odoh: send; elapsed: %s; err? %v", elapsed, qerr)
	if qerr != nil {
		res = xdns.Servfail(q) // servfail on the original query
		return
	}

	oans, err := odoh.UnmarshalDNSMessage(res)
	if err != nil {
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}

	res, err = odohctx.OpenAnswer(oans)
	if err != nil {
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	log.V("odoh: success; res: %d", len(res))
	return
}

func (t *transport) customizeForOdoh(req *http.Request) {
	req.Header.Set("content-type", odohmimetype)
	req.Header.Add("accept", odohmimetype)
	query := req.URL.Query()
	query.Add("targethost", t.odohtargetname)
	query.Add("targetpath", t.odohtargetpath)
	req.URL.RawQuery = query.Encode()
}

func (d *transport) buildTargetQuery(q []byte) (m odoh.ObliviousDNSMessage, ctx odoh.QueryContext, err error) {
	ocfg, err := d.fetchTargetConfig()
	if err != nil {
		return
	}
	if ocfg == nil {
		err = errZeroOdohCfgs
		return
	}
	key := ocfg.Contents
	pad := computePaddingSize(len(q), PaddingBlockSize)
	oq := odoh.CreateObliviousDNSQuery(q, uint16(pad))
	log.V("odoh: build-target: odoh qlen %d", len(oq.DnsMessage)+len(oq.Padding))
	return key.EncryptQuery(oq)
}

// Get the current (cached) target config or refresh it if expired.
func (d *transport) fetchTargetConfig() (*odoh.ObliviousDoHConfig, error) {
	d.omu.RLock()
	ok1 := d.odohConfig != nil
	ok2 := time.Now().Before(d.odohConfigExpiry)
	d.omu.RUnlock()

	if ok1 && ok2 { // return cached config
		log.V("odoh: fetch-target: using cached config")
		return d.odohConfig, nil
	}
	cfg, exp, err := d.refreshTargetKey()
	if err != nil {
		return nil, err
	}
	d.omu.Lock()
	d.odohConfig, d.odohConfigExpiry = cfg, exp
	d.omu.Unlock()

	log.V("odoh: fetch-target: using refereshed config; expiring: %s", exp)
	return cfg, nil
}

func (d *transport) refreshTargetKey() (ocfg *odoh.ObliviousDoHConfig, exp time.Time, err error) {
	var cq []byte
	cmsg := new(dns.Msg)
	cmsg.SetQuestion(dns.Fqdn(d.odohtargetname), dns.TypeHTTPS)
	cq, err = cmsg.Pack()
	if err != nil {
		return
	}

	req, err := d.asDohRequest(cq)
	if err != nil {
		return
	}
	cr, _, t1, qerr := d.send(req)

	log.D("odoh: refresh-target: got config; elapsed: %dms; err? %v", t1.Milliseconds(), qerr)
	if qerr != nil {
		err = qerr.Unwrap()
		return
	}

	cres := xdns.AsMsg(cr)
	if cres == nil || len(cres.Answer) <= 0 {
		log.W("odoh: refresh-target: no config ans")
		err = errNoOdohCfgResponse
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
				log.V("odoh: refresh-target: got config; config: %v; expiring: %s", ocfg, exp)
				return
			} else {
				log.D("odoh: refresh-target: not a svcblocal value; next")
			}
		}
	}

	log.W("odoh: no valid cfg in https/svcb records %d", len(cres.Answer))
	err = errNoOdohCfgResponse
	return
}

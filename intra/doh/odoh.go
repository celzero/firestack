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
	"github.com/celzero/firestack/intra/xdns"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

// adopted from: github.com/folbricht/routedns/pull/118

const odohmimetype = "application/oblivious-dns-message"

var errNoOdohCfgResponse = errors.New("no odoh config response")
var errZeroOdohCfgs = errors.New("no odoh configs found")

func (d *transport) doOdoh(q []byte) (res []byte, elapsed time.Duration, qerr *dnsx.QueryError) {
	start := time.Now()
	defer func() {
		elapsed = time.Since(start)
	}()

	odohmsg, odohctx, err := d.buildTargetQuery(q)
	if err != nil {
		qerr = dnsx.NewBadQueryError(err)
		return
	}

	oq := odohmsg.Marshal()
	res, _, elapsed, qerr = d.send(oq)
	if qerr != nil {
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
	return key.EncryptQuery(oq)
}

// Get the current (cached) target config or refresh it if expired.
func (d *transport) fetchTargetConfig() (*odoh.ObliviousDoHConfig, error) {
	d.omu.RLock()
	ok1 := d.odohConfig != nil
	ok2 := time.Now().Before(d.odohConfigExpiry)
	d.omu.RUnlock()

	if ok1 && ok2 { // return cached config
		return d.odohConfig, nil
	}
	cfg, exp, err := d.refreshTargetKey()
	if err != nil {
		return nil, err
	}
	d.omu.Lock()
	d.odohConfig, d.odohConfigExpiry = cfg, exp
	d.omu.Unlock()
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

	cr, _, _, qerr := d.send(cq)
	if qerr != nil {
		err = qerr.Unwrap()
		return
	}

	cres := xdns.AsMsg(cr)
	if cres == nil || len(cres.Answer) <= 0 {
		err = errNoOdohCfgResponse
		return
	}

	for _, rec := range cres.Answer {
		https, ok := rec.(*dns.HTTPS)
		if !ok {
			continue
		}
		ttlsec := time.Duration(rec.Header().Ttl) * time.Second
		for _, kv := range https.Value {
			if kv.Key() != 32769 {
				continue
			}
			var ocfgs odoh.ObliviousDoHConfigs
			if svcblocal, ok := kv.(*dns.SVCBLocal); ok {
				ocfgs, err = odoh.UnmarshalObliviousDoHConfigs(svcblocal.Data)
				if err != nil {
					return
				} else if len(ocfgs.Configs) <= 0 {
					err = errZeroOdohCfgs
					return
				}
				ocfg = &ocfgs.Configs[0]
				exp = time.Now().Add(ttlsec)
				return
			} // else: continue
		}
	}
	err = errNoOdohCfgResponse
	return
}

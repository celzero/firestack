// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"errors"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

// question

func (r *resolver) block(msg *dns.Msg) (ans *dns.Msg, blocklists string, err error) {
	b := r.rdnsl
	if b == nil {
		return nil, "", errNoRdns
	}
	if b.OnDeviceBlock() {
		ans, blocklists, err = r.applyBlocklists(msg)
		if err == nil { // blocklist enforced when err is nil
			return
		}
		// block skipped because err is set
		log.Debugf("skipping local block for %s with err %s", blocklists, err)
	} else {
		log.Debugf("forward query: no local block")
	}
	return
}

func (r *resolver) applyBlocklists(q *dns.Msg) (ans *dns.Msg, blocklists string, err error) {
	b := r.rdnsl
	if b == nil {
		return nil, "", errNoRdns
	}

	blocklists, err = b.blockQuery(q)
	if err != nil {
		return
	}
	if len(blocklists) <= 0 {
		err = errors.New("no blocklist applies")
		return
	}

	ans, err = xdns.RefusedResponseFromMessage(q)

	return
}

// answer

func (r *resolver) blockRes(q *dns.Msg, ans *dns.Msg, blocklistStamp string) (finalans *dns.Msg, blocklistNames string) {
	// remote block resolution, if any
	br := r.rdnsr
	var err error
	if len(blocklistStamp) > 0 && br != nil {
		blocklistNames, err = br.StampToNames(blocklistStamp)
		if err != nil {
			log.Errorf("could not resolve blocklist-stamp(%s), err: %v", blocklistStamp, err)
			return
		}
		log.Debugf(blocklistNames)
		return
	}

	// local block resolution, if any
	b := r.rdnsl
	if b == nil {
		return nil, ""
	}

	if !b.OnDeviceBlock() {
		return
	}

	if blocklistNames, err = b.blockAnswer(ans); err != nil {
		log.Debugf("response not blocked %v", err)
		return
	}

	if len(blocklistNames) <= 0 {
		log.Debugf("query not blocked blocklist empty")
		return
	}

	finalans, err = xdns.RefusedResponseFromMessage(q)
	if err != nil {
		log.Warnf("could not pack blocked dns ans %v", err)
		return
	}

	return
}

// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

func (r *resolver) blockQ(t Transport, msg *dns.Msg) (ans *dns.Msg, blocklists string, err error) {
	if t != nil && (t.ID() == Alg || t.ID() == BlockFree) {
		return nil, "", errBlockFreeTransport
	}

	qname := xdns.QName(msg)
	b := r.rdnsl

	if b == nil || !b.OnDeviceBlock() {
		return nil, "", errNoRdns
	}
	// OnDeviceBlock() is true; enforce blocklists
	ans, blocklists, err = r.applyBlocklists(msg)
	if err != nil {
		// block skipped because err is set
		log.Debugf("wall: skip local for %s block for %s with err %s", qname, blocklists, err)
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
		err = errNoBlocklistMatch
		return
	}

	ans, err = xdns.RefusedResponseFromMessage(q)

	return
}

// answer

func (r *resolver) blockA(t Transport, q *dns.Msg, ans *dns.Msg, blocklistStamp string) (finalans *dns.Msg, blocklistNames string) {
	br := r.rdnsr
	var err error
	qname := xdns.QName(q)

	// remote block resolution, if any
	if len(blocklistStamp) > 0 && br != nil {
		blocklistNames, err = br.StampToNames(blocklistStamp)
		if err != nil {
			log.Errorf("wall: could not resolve blocklist-stamp(%s) for %s, err: %v", blocklistStamp, qname, err)
			return
		}
		log.Debugf("wall: for %s blocklists %s", qname, blocklistNames)
		return
	} else {
		log.Debugf("wall: no block for %s; blocklist-stamp? (%d) / rdnsr? (%t)", qname, len(blocklistStamp), br != nil)
	}

	// skip local blocks for alg and blockfree
	if t != nil && (t.ID() == Alg || t.ID() == BlockFree) {
		return
	}

	// local block resolution, if any
	b := r.rdnsl
	if b == nil {
		return nil, ""
	}

	if !b.OnDeviceBlock() {
		log.Debugf("wall: no local block for %s", qname)
		return
	}

	if blocklistNames, err = b.blockAnswer(ans); err != nil {
		log.Debugf("wall: response for %s not blocked %v", qname, err)
		return
	}

	if len(blocklistNames) <= 0 {
		log.Debugf("wall: query %s not blocked blocklist empty", qname)
		return
	}

	finalans, err = xdns.RefusedResponseFromMessage(q)
	if err != nil {
		log.Warnf("wall: could not pack %s blocked dns ans %v", qname, err)
		return
	}

	return
}

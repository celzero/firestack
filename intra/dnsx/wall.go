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

func (r *resolver) blockQ(t, t2 Transport, msg *dns.Msg) (ans *dns.Msg, blocklists string, err error) {
	if skipBlock(t, t2) {
		return nil, "", errBlockFreeTransport
	}

	qname := xdns.QName(msg)
	b := r.rdnsl

	if b == nil || !b.OnDeviceBlock() {
		log.V("wall: no local blockerQ; letting through %s", qname)
		return nil, "", errNoRdns
	}
	// OnDeviceBlock() is true; enforce blocklists
	ans, blocklists, err = applyBlocklists(b, msg)
	if err != nil {
		// block skipped because err is set
		log.D("wall: skip local for %s blockQ for %s with err %s", qname, blocklists, err)
	}
	return
}

func applyBlocklists(b RDNS, q *dns.Msg) (ans *dns.Msg, blocklists string, err error) {
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

func (r *resolver) blockA(t, t2 Transport, q *dns.Msg, ans *dns.Msg, blocklistStamp string) (finalans *dns.Msg, blocklistNames string) {
	br := r.rdnsr
	var err error
	qname := xdns.QName(q)

	if len(blocklistStamp) > 0 && br != nil { // remote block resolution, if any
		blocklistNames, err = br.StampToNames(blocklistStamp)
		if err == nil {
			log.D("wall: for %s blocklists %s", qname, blocklistNames)
			return
		} else {
			log.D("wall: could not resolve blocklist-stamp(%s) for %s, err: %v", blocklistStamp, qname, err)
		} // continue to local block resolution
	} else {
		log.D("wall: no blockA for %s; blocklist-stamp? (%d) / rdnsr? (%t)", qname, len(blocklistStamp), br != nil)
	}

	if skipBlock(t, t2) {
		return // skip local blocks for alg and blockfree
	}

	b := r.rdnsl // local block resolution, if any
	if b == nil {
		log.V("wall: no local blockerA; letting through %s", qname)
		return nil, ""
	}

	if !b.OnDeviceBlock() {
		log.D("wall: no local blockA for %s", qname)
		return
	}

	if blocklistNames, err = b.blockAnswer(ans); err != nil {
		log.D("wall: answer for %s not blocked %v", qname, err)
		return
	}

	if len(blocklistNames) <= 0 {
		log.D("wall: answer %s not blocked blocklist empty", qname)
		return
	}

	finalans, err = xdns.RefusedResponseFromMessage(q)
	if err != nil {
		log.W("wall: could not pack %s blocked dns answer %v", qname, err)
		return
	}

	return
}

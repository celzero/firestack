// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

func (r *resolver) setRdnsLocal(rlocal *rethinkdnslocal) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	// rlocal can be nil
	r.rdnsl = rlocal
}

func (r *resolver) setRdnsRemote(rremote *rethinkdns) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	// rremote can be nil
	r.rdnsr = rremote
}

func (r *resolver) getRdnsLocal() *rethinkdnslocal {
	r.rmu.RLock()
	defer r.rmu.RUnlock()
	return r.rdnsl
}

func (r *resolver) getRdnsRemote() *rethinkdns {
	r.rmu.RLock()
	defer r.rmu.RUnlock()
	return r.rdnsr
}

// Implements RdnsResolver
func (r *resolver) SetRdnsLocal(t, rd, conf, filetag string) error {
	if len(t) <= 0 || len(rd) <= 0 {
		log.I("transport: unset rdns local")
		r.setRdnsLocal(nil)
		return nil
	}
	if r.closed.Load() {
		return errResolverClosed
	}

	rlocal, err := newRDNSLocal(t, rd, conf, filetag)
	r.setRdnsLocal(rlocal)
	return err
}

// Implements RdnsResolver
func (r *resolver) SetRdnsRemote(filetag string) error {
	if len(filetag) <= 0 {
		log.I("transport: unset rdns remote")
		r.setRdnsRemote(nil)
		return nil
	}
	if r.closed.Load() {
		return errResolverClosed
	}

	rremote, err := newRDNSRemote(filetag)
	r.setRdnsRemote(rremote)
	return err
}

// Implements RdnsResolver
func (r *resolver) GetRdnsLocal() (x.RDNS, error) {
	if r.closed.Load() {
		return nil, errResolverClosed
	}

	rlocal := r.getRdnsLocal()

	if rlocal != nil {
		// a non-ftrie version for across the jni boundary
		return rlocal.rethinkdns, nil
	}
	return nil, errNoRdns
}

// Implements RdnsResolver
func (r *resolver) GetRdnsRemote() (x.RDNS, error) {
	if r.closed.Load() {
		return nil, errResolverClosed
	}

	rremote := r.getRdnsRemote()
	if rremote != nil {
		// a non-ftrie version for across the jni boundary
		return rremote, nil
	}
	return nil, errNoRdns
}

// blockQ returns a refused ans if q is blocked by local blocklists; nil, otherwise.
// If t, t2 are non-nil, it skips local blocks for alg and blockfree transports.
func (r *resolver) blockQ(t, t2 Transport, msg *dns.Msg) (ans *dns.Msg, blocklists string, err error) {
	if skipBlock(t, t2) {
		return nil, "", errBlockFreeTransport
	}

	qname := xdns.QName(msg)
	b := r.getRdnsLocal()

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

// blockA blocks the answer if it is blocked by local blocklists.
// If blocklistStamp is not empty, it resolves them to blocklist names, if valid;
// and treats as if q was blocked by remote blocklists, effectively skipping local blocks.
// t, t2 can be nil. if non-nil, they are used to skip local blocks for alg and blockfree.
// If blocklistStamp is empty, it resolves the answer to blocklist names, if blocked by local blocklists.
// If blocklistStamp is empty and the answer is not blocked by local blocklists, it returns nil.
// If blocklistStamp is empty and the answer is blocked by local blocklists, it returns a refused response.
func (r *resolver) blockA(t, t2 Transport, q, ans *dns.Msg, blocklistStamp string) (finalans *dns.Msg, blocklistNames string) {
	br := r.getRdnsRemote()
	b := r.getRdnsLocal()

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

	// local block resolution, if any
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

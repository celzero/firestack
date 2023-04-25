// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"sync"

	"github.com/celzero/firestack/intra/xdns"
	"github.com/k-sone/critbitgo"
)

type CritBit interface {
	Set(string) bool
	Del(string) bool
	Has(string) bool
	Len() int
}

type critbit struct {
	sync.RWMutex
	t *critbitgo.Trie
}

func NewCritBit() CritBit {
	return &critbit{t: critbitgo.NewTrie()}
}

func reversed(s string) (b []byte) {
	return []byte(xdns.StringReverse(s))
}

func (c *critbit) Set(s string) bool {
	c.Lock()
	defer c.Unlock()

	return c.t.Insert(reversed(s), true)
}

func (c *critbit) Del(s string) bool {
	c.Lock()
	defer c.Unlock()

	_, ok := c.t.Delete(reversed(s))
	return ok
}

func (c *critbit) Has(s string) bool {
	c.RLock()
	defer c.RUnlock()

	rev := reversed(s)
	if match, _, ok := c.t.LongestPrefix(rev); ok {
		return true
	} else if len(match) == len(rev) || rev[len(match)] == '.' {
		// full match (ipvonly.arpa), or match upto a tld (.arpa)
		return true
	} else {
		return false
	}
}

func (c *critbit) Len() int {
	c.RLock()
	defer c.RUnlock()

	return c.t.Size()
}

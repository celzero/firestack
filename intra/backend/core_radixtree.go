// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import (
	"sync"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/k-sone/critbitgo"
)

// A RadixTree is a thread-safe trie that supports insertion, deletion, and prefix matching.
type RadixTree interface {
	// Adds k to the trie. Returns true if k was not already in the trie.
	Add(k string) bool
	// Sets k to v in the trie, overwriting any previous value.
	Set(k, v string)
	// Deletes k from the trie. Returns true if k was in the trie.
	Del(k string) bool
	// Gets the value of k from the trie or "" if k is not in the trie.
	Get(k string) string
	// Returns true if k is in the trie.
	Has(k string) bool
	// Returns the value of the longest prefix of k in the trie or "".
	GetAny(prefix string) string
	// Returns true if any key in the trie has the prefix.
	HasAny(prefix string) bool
	// Deletes all keys in the trie with the prefix. Returns the number of keys deleted.
	DelAll(prefix string) int32
	// Clears the trie.
	Clear()
	// Returns the number of keys in the trie.
	Len() int
}

type radix struct {
	sync.RWMutex
	t *critbitgo.Trie
}

func NewRadixTree() RadixTree {
	return &radix{t: critbitgo.NewTrie()}
}

func reversed(s string) (b []byte) {
	return []byte(xdns.StringReverse(s))
}

func (c *radix) Add(k string) bool {
	c.Lock()
	defer c.Unlock()

	return c.t.Insert(reversed(k), "")
}

func (c *radix) Set(k string, v string) {
	c.Lock()
	defer c.Unlock()

	c.t.Set(reversed(k), v)
}

func (c *radix) Del(k string) bool {
	c.Lock()
	defer c.Unlock()

	_, ok := c.t.Delete(reversed(k))
	return ok
}

func (c *radix) Has(k string) bool {
	c.RLock()
	defer c.RUnlock()

	return c.t.Contains(reversed(k))
}

func (c *radix) DelAll(prefix string) (n int32) {
	c.Lock()
	defer c.Unlock()

	keys := make([][]byte, 10)
	c.t.Allprefixed(reversed(prefix), func(k []byte, v any) bool {
		keys = append(keys, k)
		return true
	})

	for _, k := range keys {
		if _, ok := c.t.Delete(k); ok {
			n++
		}
	}
	return
}

func (c *radix) HasAny(prefix string) bool {
	return c.get(prefix) != nil
}

func (c *radix) Get(k string) (v string) {
	c.RLock()
	defer c.RUnlock()

	s, ok := c.t.Get(reversed(k))
	if ok {
		v, _ = s.(string)
	}
	return
}

func (c *radix) GetAny(prefix string) (v string) {
	if s := c.get(prefix); s != nil {
		v = *s
	}
	return
}

func (c *radix) get(str string) *string {
	c.RLock()
	defer c.RUnlock()

	rev := reversed(str)
	var v any    // value
	var s string // string(v)
	var ok bool  // rev(str) found?
	var match []byte

	if match, v, ok = c.t.LongestPrefix(rev); ok {
		// test: log.VV("radix: get: one: %s: %v %v %v", str, match, v, ok)
		if ok = len(match) == len(rev); ok {
			// full match (xyz.ipvonly.arpa); same as c.Get()
			s, ok = v.(string)
			// test: log.VV("radix: two: %s: %s %s %t", str, s, rev, ok)
		} else if ok = len(match) < len(rev) && rev[len(match)-1] == '.'; ok {
			// partial match upto a subdomain (.ipvonly.arpa); note the trailing dot
			s, ok = v.(string)
			// test: log.VV("radix: three: %s: %s %v %t", str, s, rev, ok)
		}
		// test: log.VV("radix: get: four: %s: %s [%d %d] %t", str, s, len(rev), len(match), ok)
		// partial match (ipvonly.arpa) but not a subdomain/wildcard, discard
	} else { // no match
		return nil
	}

	log.V("radix: get: partial or full %s => %s; rev %s; match %s; ok? %t", str, s, rev, match, ok)

	if !ok {
		return nil
	}
	return &s
}

func (c *radix) Clear() {
	c.Lock()
	defer c.Unlock()

	c.t.Clear()
}

func (c *radix) Len() int {
	c.RLock()
	defer c.RUnlock()

	return c.t.Size()
}

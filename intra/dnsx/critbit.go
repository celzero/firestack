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

// A CritBit is a thread-safe trie that supports insertion, deletion, and prefix matching.
type CritBit interface {
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

func (c *critbit) Add(k string) bool {
	c.Lock()
	defer c.Unlock()

	return c.t.Insert(reversed(k), "")
}

func (c *critbit) Set(k string, v string) {
	c.Lock()
	defer c.Unlock()

	c.t.Set(reversed(k), v)
}

func (c *critbit) Del(k string) bool {
	c.Lock()
	defer c.Unlock()

	_, ok := c.t.Delete(reversed(k))
	return ok
}

func (c *critbit) Has(k string) bool {
	c.RLock()
	defer c.RUnlock()

	return c.t.Contains(reversed(k))
}

func (c *critbit) DelAll(prefix string) (n int32) {
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

func (c *critbit) HasAny(prefix string) bool {
	return c.get(prefix) != nil
}

func (c *critbit) Get(k string) (v string) {
	s, ok := c.t.Get(reversed(k))
	if ok {
		v = s.(string)
	}
	return
}

func (c *critbit) GetAny(prefix string) (v string) {
	if s := c.get(prefix); s != nil {
		v = *s
	}
	return
}

func (c *critbit) get(str string) *string {
	c.RLock()
	defer c.RUnlock()

	rev := reversed(str)
	var s string
	if match, v, ok := c.t.LongestPrefix(rev); ok {
		s = v.(string)
	} else if len(match) == len(rev) || rev[len(match)] == '.' {
		// full match (ipvonly.arpa), or match upto a tld (.arpa)
		s = v.(string)
	} else {
		return nil
	}
	return &s
}

func (c *critbit) Clear() {
	c.Lock()
	defer c.Unlock()

	c.t.Clear()
}

func (c *critbit) Len() int {
	c.RLock()
	defer c.RUnlock()

	return c.t.Size()
}

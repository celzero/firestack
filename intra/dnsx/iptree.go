// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/celzero/firestack/intra/log"
	"github.com/k-sone/critbitgo"
)

// A IpTree is a thread-safe trie that supports insertion, deletion, and route matching IP CIDRs.
type IpTree interface {
	// Adds value v to the cidr route in the trie.
	Add(cidr string, v string) error
	// Sets cidr route to v in the trie, overwriting any previous value.
	Set(cidr, v string) error
	// Removes value v, if found, from the trie.
	Esc(cidr string, v string) bool
	// Deletes cidr route from the trie. Returns true if cidr was in the trie.
	Del(cidr string) bool
	// Gets the value of cidr from the trie or "" if cidr is not in the trie.
	Get(cidr string) (string, error)
	// Returns true if the cidr route is in the trie.
	Has(cidr string) (bool, error)
	// Returns the route:value of the longest route for cidr in the trie or "".
	GetAny(cidr string) (string, error)
	// Returns true if any route in the trie has the route.
	HasAny(cidr string) (bool, error)
	// Deletes all routes in the trie matching cidr. Returns the number of routes deleted.
	DelAll(cidr string) int32
	// Clears the trie.
	Clear()
	// Returns the number of routes in the trie.
	Len() int
}

type iptree struct {
	sync.RWMutex
	t *critbitgo.Net
}

func NewIpTree() IpTree {
	return &iptree{t: critbitgo.NewNet()}
}

func (c *iptree) Add(cidr string, v string) error {
	if x, err := c.Get(cidr); err != nil {
		return err
	} else if len(v) == 0 || x == v {
		return nil
	} else if len(x) == 0 {
		return c.Set(cidr, v)
	} else if strings.Contains(x, v) {
		cur := strings.Split(x, ",")
		for _, val := range cur {
			if val == v {
				return nil
			}
		}
		return c.Set(cidr, x+","+v)
	} else {
		return c.Set(cidr, x+","+v)
	}
}

func (c *iptree) Set(cidr string, v string) error {
	r := ip2cidr(cidr)

	c.Lock()
	defer c.Unlock()

	return c.t.Add(r, v)
}

func (c *iptree) Del(cidr string) bool {
	r := ip2cidr(cidr)

	c.Lock()
	defer c.Unlock()

	_, ok, err := c.t.Delete(r)
	return ok && err == nil
}

func (c *iptree) Esc(cidr string, v string) bool {
	if x, err := c.Get(cidr); err != nil {
		return false
	} else if len(x) == 0 || len(v) == 0 {
		return false
	} else if x == v {
		return c.Del(cidr)
	} else if strings.Contains(x, v) {
		// remove all occurences of v in csv x
		old := strings.Split(x, ",")
		cur := make([]string, 0, len(old))
		for _, val := range old {
			if val != v {
				cur = append(cur, val)
			}
		}
		if len(cur) == 0 {
			return c.Del(cidr)
		}
		return c.Set(cidr, strings.Join(cur, ",")) == nil
	} else {
		return false
	}
}

func (c *iptree) Has(cidr string) (bool, error) {
	r := ip2cidr(cidr)

	c.RLock()
	defer c.RUnlock()

	_, ok, err := c.t.Get(r)
	return ok, err
}

func (c *iptree) DelAll(cidr string) (n int32) {
	r := ip2cidr(cidr)
	if r == nil {
		return
	}

	c.Lock()
	defer c.Unlock()

	keys := make([]*net.IPNet, 10)
	c.t.WalkMatch(r, func(k *net.IPNet, v any) bool {
		keys = append(keys, k)
		return true
	})

	for _, k := range keys {
		if _, ok, err := c.t.Delete(k); ok && err == nil {
			n++
		}
	}
	return
}

func (c *iptree) HasAny(cidr string) (bool, error) {
	r := ip2cidr(cidr)

	c.RLock()
	defer c.RUnlock()

	m, _, err := c.t.Match(r)
	return m != nil, err
}

func (c *iptree) Get(cidr string) (v string, err error) {
	r := ip2cidr(cidr)

	c.RLock()
	defer c.RUnlock()

	s, ok, err := c.t.Get(r)
	if ok && err == nil {
		v, _ = s.(string)
	}
	return
}

func (c *iptree) GetAny(cidr string) (rv string, err error) {
	r := ip2cidr(cidr)

	c.RLock()
	defer c.RUnlock()

	if m, v, err := c.t.Match(r); err != nil {
		return "", err
	} else {
		if m != nil {
			rv = m.String()
		}
		if v != nil {
			rv = rv + ":" + v.(string)
		}
	}
	return
}

func (c *iptree) Clear() {
	c.Lock()
	defer c.Unlock()

	c.t.Clear()
}

func (c *iptree) Len() int {
	c.RLock()
	defer c.RUnlock()

	return c.t.Size()
}

func ip2cidr(ipOrCidr string) *net.IPNet {
	if _, ipnet, err := net.ParseCIDR(ipOrCidr); err == nil {
		return ipnet
	} else if ipaddr, err := netip.ParseAddr(ipOrCidr); err == nil {
		ip := ipaddr.AsSlice()
		mask := net.CIDRMask(ipaddr.BitLen(), ipaddr.BitLen())
		return &net.IPNet{IP: ip, Mask: mask}
	} else {
		log.W("iptree: ip2cidr: %v", err)
	}
	return nil
}

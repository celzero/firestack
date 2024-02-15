// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"errors"
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
	Add(cidr, v string) error
	// Sets cidr route to v in the trie, overwriting any previous value.
	Set(cidr, v string) error
	// Removes value v, if found, from the trie.
	Esc(cidr, v string) bool
	// Deletes cidr route from the trie. Returns true if cidr was in the trie.
	Del(cidr string) bool
	// Gets the value of cidr from the trie or "" if cidr is not in the trie.
	Get(cidr string) (string, error)
	// Returns true if the cidr route is in the trie.
	Has(cidr string) (bool, error)
	// Returns csv of all routes for cidr in the trie or "".
	Routes(cidr string) string
	// Returns csv of values of all routes matching cidr in the trie or "".
	Values(cidr string) string
	// Returns the route@csv(value) of all routes for cidr in the trie or "".
	GetAny(cidr string) (string, error)
	// Returns true if any route in the trie has the route.
	HasAny(cidr string) (bool, error)
	// Removes values like v for cidr from the trie.
	EscLike(cidr, likev string) int32
	// Returns csv of all routes with any value like v for cidr from trie.
	RoutesLike(cidr, likev string) string
	// Returns csv of all values like v for cidr from trie.
	ValuesLike(cidr, likev string) string
	// Returns the longest route for cidr in the trie as "r1@csv(v)|r2@csv(v2)" or "".
	GetAll(cidr string) (string, error)
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

const (
	Vsep   = "," // values separator (csv)
	Ksep   = "," // key separator (csv)
	Kdelim = "@" // key@csv(v) delimiter
	KVsep  = "|" // k1:v1|k2:v2 separator
)

var (
	errValNotString = errors.New("values must be string")
)

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
		cur := strings.Split(x, Vsep)
		for _, val := range cur {
			if val == v {
				return nil
			}
		}
		return c.Set(cidr, x+Vsep+v)
	} else {
		return c.Set(cidr, x+Vsep+v)
	}
}

func (c *iptree) Set(cidr string, v string) error {
	r, err := ip2cidr(cidr)
	if err != nil {
		return err
	}

	c.Lock()
	defer c.Unlock()

	return c.t.Add(r, v)
}

func (c *iptree) Del(cidr string) bool {
	r, err := ip2cidr(cidr)
	if err != nil {
		return false
	}

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
		old := strings.Split(x, Vsep)
		cur := make([]string, 0, len(old))
		for _, val := range old {
			if val != v {
				cur = append(cur, val)
			}
		}
		if len(cur) == 0 {
			return c.Del(cidr)
		}
		return c.Set(cidr, strings.Join(cur, Vsep)) == nil
	} else {
		return false
	}
}

func (c *iptree) Has(cidr string) (bool, error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return false, err
	}

	c.RLock()
	defer c.RUnlock()

	_, ok, err := c.t.Get(r)
	return ok, err
}

func (c *iptree) DelAll(cidr string) (n int32) {
	r, err := ip2cidr(cidr)
	if r == nil || err != nil {
		return
	}

	c.Lock()
	defer c.Unlock()

	keys := make([]*net.IPNet, 0)
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
	r, err := ip2cidr(cidr)
	if err != nil {
		return false, err
	}

	c.RLock()
	defer c.RUnlock()

	m, _, err := c.t.Match(r)
	return m != nil, err
}

func (c *iptree) Get(cidr string) (v string, err error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return "", err
	}

	c.RLock()
	defer c.RUnlock()

	s, ok, err := c.t.Get(r)
	if ok && err == nil {
		if v, ok = s.(string); !ok {
			return "", errValNotString
		}
	} else {
		return "", err // may be nil
	}
	return
}

func (c *iptree) GetAny(cidr string) (rv string, err error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return "", err
	}

	c.RLock()
	defer c.RUnlock()

	if m, v, err := c.t.Match(r); err != nil {
		return "", err
	} else {
		if m != nil {
			rv = m.String()
		}
		if v != nil {
			if s, ok := v.(string); ok {
				rv = rv + Kdelim + s
			}
		}
	}
	return
}

func (c *iptree) GetAll(cidr string) (rv string, errs error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return "", err
	}

	c.RLock()
	defer c.RUnlock()

	c.t.WalkMatch(r, func(k *net.IPNet, v any) bool {
		if k == nil {
			return true // next
		}
		rv = rv + k.String()
		if v != nil {
			if s, ok := v.(string); ok && len(s) > 0 {
				rv = rv + Kdelim + s
			}
		}
		rv = rv + KVsep
		return true // next
	})
	return strings.TrimRight(rv, KVsep), nil
}

func (c *iptree) Routes(cidr string) string {
	r, err := ip2cidr(cidr)
	if err != nil {
		return ""
	}

	c.RLock()
	defer c.RUnlock()

	rt := make([]string, 0)
	c.t.WalkMatch(r, func(k *net.IPNet, v any) bool {
		if k != nil {
			rt = append(rt, k.String())
		}
		return true // next
	})
	return strings.Join(rt, Ksep)
}

func (c *iptree) Values(cidr string) string {
	r, err := ip2cidr(cidr)
	if err != nil {
		return ""
	}

	c.RLock()
	defer c.RUnlock()

	vt := make([]string, 0)
	c.t.WalkMatch(r, func(k *net.IPNet, v any) bool {
		if v != nil {
			if s, ok := v.(string); ok && len(s) > 0 {
				vt = append(vt, s)
			}
		}
		return true // next
	})
	return strings.Join(vt, Vsep)
}

func (c *iptree) EscLike(cidr, like string) int32 {
	if x, err := c.Get(cidr); err != nil {
		return -1 // error
	} else if len(x) == 0 {
		return 0
	} else if len(like) == 0 {
		return c.DelAll(cidr)
	} else if x == like {
		if rmv := c.Del(cidr); rmv {
			return 1
		}
		return 0
	} else if strings.Contains(x, like) {
		// remove all occurences of v in csv x
		old := strings.Split(x, Vsep)
		cur := make([]string, 0, len(old))
		n := int32(0)
		for _, val := range old {
			if !strings.Contains(val, like) {
				cur = append(cur, val)
			} else {
				n++
			}
		}
		if len(cur) == 0 { // no values left
			_ = c.Del(cidr)
		} else if len(cur) != len(old) { // no change; n == 0
			_ = c.Set(cidr, strings.Join(cur, Vsep))
		}
		return n
	} else {
		return 0 // not found
	}
}

func (c *iptree) RoutesLike(cidr, like string) string {
	r, err := ip2cidr(cidr)
	if err != nil {
		return ""
	}

	c.RLock()
	defer c.RUnlock()

	rt := make([]string, 0)
	c.t.WalkMatch(r, func(k *net.IPNet, v any) bool {
		if v != nil {
			if s, ok := v.(string); ok && len(s) > 0 {
				if strings.Contains(s, like) {
					rt = append(rt, k.String())
				}
			}
		}
		return true // next
	})
	return strings.Join(rt, Ksep)
}

func (c *iptree) ValuesLike(cidr, like string) string {
	r, err := ip2cidr(cidr)
	if err != nil {
		return ""
	}

	c.RLock()
	defer c.RUnlock()

	vt := make([]string, 0)
	c.t.WalkMatch(r, func(k *net.IPNet, v any) bool {
		if v != nil {
			if s, ok := v.(string); ok && len(s) > 0 {
				if strings.Contains(s, like) {
					vt = append(vt, s)
				}
			}
		}
		return true // next
	})
	return strings.Join(vt, Vsep)
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

func ip2cidr(ipOrCidr string) (ipnet *net.IPNet, err error) {
	var ipaddr netip.Addr
	if _, ipnet, err = net.ParseCIDR(ipOrCidr); err == nil {
		return
	} else if ipaddr, err = netip.ParseAddr(ipOrCidr); err == nil {
		ip := ipaddr.AsSlice()
		mask := net.CIDRMask(ipaddr.BitLen(), ipaddr.BitLen())
		ipnet = &net.IPNet{IP: ip, Mask: mask}
	} else {
		log.W("iptree: ip2cidr: %v", err)
	}
	return
}

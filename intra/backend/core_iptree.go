// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import (
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/celzero/firestack/intra/core"
	"github.com/k-sone/critbitgo"
)

// todo: use github.com/gaissmai/bart ?

// A IpTree is a thread-safe trie that supports insertion, deletion, and route matching IP CIDRs.
type IpTree interface {
	// Adds value v to the cidr route.
	Add(cidr, v string) error
	// Sets cidr route to v, overwriting any previous value.
	Set(cidr, v string) error
	// Removes value v, if found.
	Esc(cidr, v string) bool
	// Deletes cidr route. Returns true if cidr was found.
	Del(cidr string) bool
	// Gets the value of cidr or "" if cidr is not found.
	Get(cidr string) (string, error)
	// Returns true if the cidr route is found.
	Has(cidr string) (bool, error)
	// Returns csv of all routes matching cidr or "".
	Routes(cidr string) string
	// Returns csv of values of all routes matching cidr or "".
	Values(cidr string) string
	// Returns the route@csv(value) of any route matching cidr or "".
	GetAny(cidr string) (string, error)
	// Returns true if any route matches cidr.
	HasAny(cidr string) (bool, error)
	// Removes values like v ("*v*") for cidr.
	EscLike(cidr, likev string) int32
	// Returns csv of all routes with any value like v matching cidr.
	RoutesLike(cidr, likev string) string
	// Returns csv of all routes with values like v for cidr.
	ValuesLike(cidr, likev string) string
	// Returns csv of all values like v for cidr.
	GetLike(cidr, likev string) string
	// Returns the longest route for cidr as "r1@csv(v)|r2@csv(v2)" or "".
	GetAll(cidr string) (string, error)
	// Deletes all routes matching cidr. Returns the number of routes deleted.
	DelAll(cidr string) int32
	// Clears the trie.
	Clear()
	// Returns the number of routes.
	Len() int
}

type iptree struct {
	sync.RWMutex
	t4 *critbitgo.Net // IPv4 routes
	t6 *critbitgo.Net // IPv6 routes
}

const (
	// Vsep is a values separator (csv)
	Vsep = ","
	// Ksep is a key separator (csv)
	Ksep = ","
	// Kdelim is a key@csv(v) delimiter
	Kdelim = "@"
	// KVsep is a k1:v1|k2:v2 separator
	KVsep = "|"
)

var (
	errValNotString = errors.New("values must be string")
)

// NewIpTree returns a new IpTree.
func NewIpTree() IpTree {
	return &iptree{
		t4: critbitgo.NewNet(),
		t6: critbitgo.NewNet(),
	}
}

// net returns the trie for the address family of r.
func (c *iptree) net(r *net.IPNet) *critbitgo.Net {
	if r.IP.To4() != nil {
		return c.t4
	}
	return c.t6
}

func (c *iptree) Add(cidr string, v string) error {
	return c.add(cidr, v)
}

func (c *iptree) add(cidr string, v string) error {
	x, err := c.get(cidr)

	if err != nil {
		return err
	} else if len(v) == 0 || x == v {
		return nil
	} else if len(x) == 0 {
		return c.set(cidr, v)
	} else if strings.Contains(x, v) { // is ~v in x?
		cur := strings.SplitSeq(x, Vsep)
		for val := range cur {
			if val == v { // v is definitely in x
				return nil
			}
		} // v is not in x, but something resembling ~v was.
		return c.set(cidr, x+Vsep+v)
	}
	return c.set(cidr, x+Vsep+v)
}

func (c *iptree) Set(cidr string, v string) error {
	c.del(cidr) // delete any previous value
	return c.add(cidr, v)
}

func (c *iptree) set(cidr string, v string) error {
	r, err := ip2cidr(cidr)
	if err != nil {
		return err
	}

	t := c.net(r)
	c.Lock()
	defer c.Unlock()

	return t.Add(r, v)
}

func (c *iptree) Del(cidr string) bool {
	return c.del(cidr)
}

func (c *iptree) del(cidr string) bool {
	r, err := ip2cidr(cidr)
	if err != nil {
		return false
	}

	t := c.net(r)
	c.Lock()
	defer c.Unlock()

	_, ok, err := t.Delete(r)
	return ok && err == nil
}

func (c *iptree) Esc(cidr string, v string) bool {
	return c.esc(cidr, v)
}

func (c *iptree) esc(cidr string, v string) bool {
	if x, err := c.get(cidr); err != nil {
		return false
	} else if len(x) == 0 || len(v) == 0 {
		return false
	} else if x == v {
		return c.del(cidr)
	} else if strings.Contains(x, v) {
		// remove all occurrences of v in csv x
		old := strings.Split(x, Vsep)
		cur := make([]string, 0, len(old))
		for _, val := range old {
			if val != v {
				cur = append(cur, val)
			}
		}
		if len(cur) == 0 {
			return c.del(cidr)
		}
		return c.set(cidr, strings.Join(cur, Vsep)) == nil
	}
	return false
}

func (c *iptree) Has(cidr string) (bool, error) {
	return c.has(cidr)
}

func (c *iptree) has(cidr string) (bool, error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return false, err
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	_, ok, err := t.Get(r)
	return ok, err
}

func (c *iptree) DelAll(cidr string) (n int32) {
	return c.delAll(cidr)
}

func (c *iptree) delAll(cidr string) (n int32) {
	r, err := ip2cidr(cidr)
	if r == nil || err != nil {
		return
	}

	t := c.net(r)
	c.Lock()
	defer c.Unlock()

	keys := make([]*net.IPNet, 0)
	t.WalkMatch(r, func(k *net.IPNet, _ any) bool {
		keys = append(keys, k)
		return true
	})

	for _, k := range keys {
		if _, ok, err := t.Delete(k); ok && err == nil {
			n++
		}
	}
	return
}

func (c *iptree) HasAny(cidr string) (bool, error) {
	return c.hasAny(cidr)
}

func (c *iptree) hasAny(cidr string) (bool, error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return false, err
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	m, _, err := t.Match(r)
	return m != nil, err
}

func (c *iptree) Get(cidr string) (string, error) {
	r, err := c.get(cidr)
	if err != nil {
		return "", err
	}
	return r, nil // r may be empty
}

func (c *iptree) get(cidr string) (v string, err error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return "", err
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	s, ok, err := t.Get(r)
	if ok && err == nil {
		if v, ok = s.(string); !ok {
			return "", errValNotString
		}
	} else {
		return "", err // may be nil
	}
	return
}

func (c *iptree) GetAny(cidr string) (string, error) {
	r, err := c.getAny(cidr)
	if err != nil {
		return "", err
	}
	return r, nil // r may be empty
}

func (c *iptree) getAny(cidr string) (rv string, err error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return "", err
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	m, v, err := t.Match(r)
	if err != nil {
		return "", err
	}
	if m != nil {
		rv = m.String()
	}
	if v != nil {
		if s, ok := v.(string); ok {
			rv = rv + Kdelim + s
		}
	}
	return
}

func (c *iptree) GetAll(cidr string) (string, error) {
	r, err := c.getAll(cidr)
	if err != nil {
		return "", err
	}
	return r, nil // r may be empty
}

func (c *iptree) getAll(cidr string) (rv string, err error) {
	r, err := ip2cidr(cidr)
	if err != nil {
		return "", err
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	t.WalkMatch(r, func(k *net.IPNet, v any) bool {
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
	return c.routes(cidr)
}

func (c *iptree) routes(cidr string) string {
	r, err := ip2cidr(cidr)
	if err != nil {
		return ""
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	rt := make([]string, 0)
	t.WalkMatch(r, func(k *net.IPNet, _ any) bool {
		if k != nil {
			rt = append(rt, k.String())
		}
		return true // next
	})
	return strings.Join(rt, Ksep)
}

func (c *iptree) Values(cidr string) string {
	return c.values(cidr)
}

func (c *iptree) values(cidr string) string {
	r, err := ip2cidr(cidr)
	if err != nil {
		return ""
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	vt := make([]string, 0)
	t.WalkMatch(r, func(_ *net.IPNet, v any) bool {
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
	return c.escLike(cidr, like)
}

func (c *iptree) escLike(cidr, like string) int32 {
	if x, err := c.get(cidr); err != nil {
		return -1 // error
	} else if len(x) == 0 {
		return 0
	} else if len(like) == 0 {
		return c.delAll(cidr)
	} else if x == like {
		if rmv := c.del(cidr); rmv {
			return 1
		}
		return 0
	} else if strings.Contains(x, like) {
		// remove all occurrences of v in csv x
		old := strings.Split(x, Vsep)
		cur := make([]string, 0, len(old))
		n := int32(0)
		for _, val := range old {
			if !strings.HasPrefix(val, like) {
				cur = append(cur, val)
			} else {
				n++
			}
		}
		if len(cur) == 0 { // no values left
			_ = c.del(cidr)
		} else if len(cur) != len(old) { // no change; n == 0
			_ = c.set(cidr, strings.Join(cur, Vsep))
		}
		return n
	}
	return 0 // not found
}

func (c *iptree) GetLike(cidr, like string) string {
	return c.getLike(cidr, like)
}

func (c *iptree) getLike(cidr, like string) string {
	if x, err := c.get(cidr); err != nil {
		return "" // error
	} else if len(x) == 0 {
		return ""
	} else if len(like) == 0 || x == like {
		return x // match all
	} else if strings.Contains(x, like) {
		// grab all occurrences of v in csv x
		all := strings.Split(x, Vsep)
		grab := make([]string, 0, len(all))
		for _, val := range all {
			if strings.HasPrefix(val, like) {
				grab = append(grab, val)
			}
		}
		return strings.Join(grab, Vsep)
	}
	return "" // not found
}

func (c *iptree) RoutesLike(cidr, like string) string {
	return c.routesLike(cidr, like)
}

func (c *iptree) routesLike(cidr, like string) string {
	r, err := ip2cidr(cidr)
	if err != nil {
		return ""
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	rt := make([]string, 0)
	t.WalkMatch(r, func(k *net.IPNet, v any) bool {
		if v == nil {
			return true // next
		}
		if s, ok := v.(string); ok && len(s) > 0 {
			if !strings.Contains(s, like) {
				return true // next
			}
			// grab all occurrences of v in csv s
			for val := range strings.SplitSeq(s, Vsep) {
				if strings.HasPrefix(val, like) {
					rt = append(rt, val)
				}
			}
		}
		return true // next
	})
	return strings.Join(rt, Ksep)
}

func (c *iptree) ValuesLike(cidr, like string) string {
	return c.valuesLike(cidr, like)
}

func (c *iptree) valuesLike(cidr, like string) string {
	r, err := ip2cidr(cidr)
	if err != nil {
		return ""
	}

	t := c.net(r)
	c.RLock()
	defer c.RUnlock()

	vt := make([]string, 0)
	t.WalkMatch(r, func(k *net.IPNet, v any) bool {
		if v == nil {
			return true // next
		}
		if s, ok := v.(string); ok && len(s) > 0 {
			if !strings.Contains(s, like) {
				return true // next
			}
			// grab all occurrences of v in csv s
			for val := range strings.SplitSeq(s, Vsep) {
				if strings.HasPrefix(val, like) {
					vt = append(vt, val)
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

	c.t4.Clear()
	c.t6.Clear()
}

func (c *iptree) Len() int {
	c.RLock()
	defer c.RUnlock()

	return c.t4.Size() + c.t6.Size()
}

func ip2cidr(ippOrCidr string) (*net.IPNet, error) {
	return core.IP2Cidr(ippOrCidr)
}

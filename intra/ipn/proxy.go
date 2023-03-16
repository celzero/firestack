// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"net/url"

	"github.com/celzero/firestack/intra/settings"
)

func (pxr *proxifier) NewSocks5Proxy(id, user, pwd, ip, port string) (p Proxy, err error) {
	opts := settings.NewAuthProxyOptions("socks5", user, pwd, ip, port)
	return NewSocks5Proxy(id, pxr.ctl, opts)
}

func (pxr *proxifier) AddProxy(id, rawurl string) (p Proxy, err error) {
	var strurl string
	var usr string
	var pwd string

	// scheme://usr:pwd@domain.tld:8080/p/a/t/h?q&u=e&r=y
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	if u.User != nil {
		usr = u.User.Username()    // usr
		pwd, _ = u.User.Password() // pwd
	}
	strurl = u.Host + u.RequestURI() // domain.tld:8080/p/a/t/h?q&u=e&r=y

	opts := settings.NewAuthProxyOptions(u.Scheme, usr, pwd, strurl, u.Port())

	var proxy Proxy
	switch u.Scheme {
	case "socks5":
		proxy, err = NewSocks5Proxy(id, pxr.ctl, opts)
	case "http":
		fallthrough
	case "https":
		proxy, err = NewHTTPProxy(id, pxr.ctl, opts)
	default:
		return nil, errProxyScheme
	}

	if err != nil {
		return nil, err
	} else if ok := pxr.add(proxy); !ok {
		return nil, errProxyScheme
	}

	return proxy, nil
}

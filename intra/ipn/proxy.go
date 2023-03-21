// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

func (pxr *proxifier) NewSocks5Proxy(id, user, pwd, ip, port string) (p Proxy, err error) {
	opts := settings.NewAuthProxyOptions("socks5", user, pwd, ip, port)
	return NewSocks5Proxy(id, pxr.ctl, opts)
}

func (pxr *proxifier) AddProxy(id, txt string) (p Proxy, err error) {
	// wireguard proxies have IDs starting with "wg"
	if strings.HasPrefix(id, WG) {
		if p, _ = pxr.GetProxy(id); p != nil {
			if wgp, ok := p.(WgProxy); ok {
				log.I("proxy: updating wg %s/%s", p.ID(), p.GetAddr())
				err = wgp.IpcSet(txt)
				return
			} else {
				return nil, errUnexpectedProxy
			}
		} else {
			// txt is both wg ifconfig and peercfg
			p, err = NewWgProxy(id, pxr.ctl, txt)
		}
	} else {
		var strurl string
		var usr string
		var pwd string

		// scheme://usr:pwd@domain.tld:8080/p/a/t/h?q&u=e&r=y
		u, err := url.Parse(txt)
		if err != nil {
			return nil, err
		}

		if u.User != nil {
			usr = u.User.Username()    // usr
			pwd, _ = u.User.Password() // pwd
		}
		strurl = u.Host + u.RequestURI() // domain.tld:8080/p/a/t/h?q&u=e&r=y

		opts := settings.NewAuthProxyOptions(u.Scheme, usr, pwd, strurl, u.Port())

		switch u.Scheme {
		case "socks5":
			p, err = NewSocks5Proxy(id, pxr.ctl, opts)
		case "http":
			fallthrough
		case "https":
			p, err = NewHTTPProxy(id, pxr.ctl, opts)
		case "wg":
			err = fmt.Errorf("proxy: id must be prefixed with %s in %s for [%s]", WG, id, txt)
			fallthrough
		default:
			return nil, errProxyScheme
		}
	}

	if err != nil {
		return nil, err
	} else if ok := pxr.add(p); !ok {
		return nil, errAddProxy
	}

	log.I("proxy: added %s/%s/%s", p.ID(), p.Type(), p.GetAddr())
	return
}

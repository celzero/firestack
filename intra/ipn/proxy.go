// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

func (pxr *proxifier) NewSocks5Proxy(id, user, pwd, ip, port string) (p Proxy, err error) {
	opts := settings.NewAuthProxyOptions("socks5", user, pwd, ip, port, nil)
	return NewSocks5Proxy(id, pxr.ctl, opts)
}

func (pxr *proxifier) AddProxy(id, txt string) (x.Proxy, error) {
	return pxr.addProxy(id, txt)
}

func (pxr *proxifier) addProxy(id, txt string) (p Proxy, err error) {
	// wireguard proxies have IDs starting with "wg"
	if strings.HasPrefix(id, WG) {
		if p, _ = pxr.ProxyFor(id); p != nil {
			if wgp, ok := p.(WgProxy); ok && wgp.canUpdate(txt) {
				log.I("proxy: updating wg %s/%s", id, p.GetAddr())

				ifaddrs, _, dnsh, _, mtu, err0 := wgIfConfigOf(&txt) // removes wg ifconfig from txt
				if err0 != nil {
					log.W("proxy: err0 updating wg(%s); %v", id, err0)
					return nil, err0
				} else {
					log.V("proxy: updating wg(%s); ifaddrs(%v), dns(%v), mtu(%d)", id, ifaddrs, dnsh, mtu)
				}

				err1 := wgp.IpcSet(txt)
				if err1 != nil {
					log.W("proxy: err1 updating wg(%s); %v", id, err1)
					return nil, err1
				} else {
					// sensitive log: peercfg contains private key
					log.P("proxy: updating wg(%s) len(peercfg(%s))", id, len(txt))
				}

				err2 := wgp.Refresh()
				if err2 != nil {
					log.W("proxy: err2 updating wg(%s); %v", id, err2)
					return nil, err2
				}
				return
			} // else: create anew
		}
		// txt is both wg ifconfig and peercfg
		p, err = NewWgProxy(id, pxr.ctl, txt)
	} else {
		var strurl string
		var usr string
		var pwd string
		var u *url.URL
		// scheme://usr:pwd@domain.tld:8080/p/a/t/h?q&u=e&r=y
		u, err = url.Parse(txt)
		if err != nil {
			return nil, err
		}

		if u.User != nil {
			usr = u.User.Username()    // usr
			pwd, _ = u.User.Password() // pwd
		}
		strurl = u.Host + u.RequestURI() // domain.tld:8080/p/a/t/h?q&u=e&r=y#f,r
		addrs := strings.Split(u.Fragment, ",")
		// opts may be nil
		opts := settings.NewAuthProxyOptions(u.Scheme, usr, pwd, strurl, u.Port(), addrs)

		switch u.Scheme {
		case "socks5":
			p, err = NewSocks5Proxy(id, pxr.ctl, opts)
		case "http":
			fallthrough
		case "https":
			p, err = NewHTTPProxy(id, pxr.ctl, opts)
		case "piph2":
			p, err = NewPipProxy(id, pxr.ctl, opts)
		case "pipws":
			p, err = NewPipWsProxy(id, pxr.ctl, opts)
		case "wg":
			err = fmt.Errorf("proxy: id must be prefixed with %s in %s for [%s]", WG, id, txt)
		default:
			err = errProxyScheme
		}
	}

	if err != nil {
		return nil, err
	} else if p == nil {
		return nil, errAddProxy
	} else if ok := pxr.add(p); !ok {
		return nil, errAddProxy
	}

	log.I("proxy: added %s/%s/%s", p.ID(), p.Type(), p.GetAddr())
	return
}

func Fetch(p Proxy, req *http.Request) (*http.Response, error) {
	return p.fetch(req)
}

func newRDial(p Proxy) *protect.RDial {
	return &protect.RDial{
		Owner:   p.ID(),
		RDialer: p,
	}
}

func newHTTPClient(d *protect.RDial) *http.Client {
	c := &http.Client{}
	c.Transport = &http.Transport{
		Dial:                  d.Dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	return c
}

func newHTTP1Client(d *protect.RDial) *http.Client {
	c := &http.Client{}
	c.Transport = &http.Transport{
		Dial:                  d.Dial,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	return c
}

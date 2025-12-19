// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package settings

import (
	"net"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/net/proxy"
)

// ProxyOptions define https or socks5 proxy options
type ProxyOptions struct {
	Auth   *proxy.Auth
	IP     string   // just the ip
	Host   string   // just the hostname (no port)
	Port   string   // just the port number
	IPPort string   // may be a url or ip:port
	Scheme string   // http, https, socks5, pip
	Addrs  []string // list of ips if ipport is a url; may be nil
}

// NewAuthProxyOptions returns a new ProxyOptions object with authentication object.
func NewAuthProxyOptions(scheme, username, password, ip, port string, addrs []string) *ProxyOptions {
	var ippstr string
	var ipstr string
	var host string
	ip = strings.TrimSuffix(ip, "/")
	ipp, err := addrport(ip, port)
	if err != nil {
		log.I("proxyopt: scheme %s; ipport(%s:%s) is url?(%v)", scheme, ip, port, err)
		if len(ip) > 0 {
			// port is discarded, and expected to be in ip/url
			ippstr = ip
			host, port, _ = net.SplitHostPort(ip)
		} else if len(port) > 0 {
			// incoming ip,port is a wildcard address
			ippstr = ":" + port
		} else {
			return nil
		}
	} else {
		ippstr = ipp.String()
		ipstr = ipp.Addr().String()
	}
	if len(username) <= 0 || len(password) <= 0 {
		log.I("proxyopt: no user(%s) and/or pwd(%d)", username, len(password))
	}
	if len(scheme) <= 0 {
		scheme = "http"
	}
	// todo: query unescape username and password?
	auth := proxy.Auth{
		User:     username,
		Password: password,
	}
	return &ProxyOptions{
		Auth:   &auth,
		Host:   host,   // may be empty or hostname (without port)
		IP:     ipstr,  // may be empty or ipaddr
		Port:   port,   // port number
		IPPort: ippstr, // may be ip4:port, [ip::6]:port, host:port, or :port
		Scheme: scheme,
		Addrs:  addrs, // may be empty
	}
}

// NewProxyOptions returns a new ProxyOptions object.
func NewProxyOptions(ip string, port string) *ProxyOptions {
	return NewAuthProxyOptions("" /*scheme*/, "" /*user*/, "" /*password*/, ip, port /*addrs*/, nil)
}

func (p *ProxyOptions) String() string {
	if p == nil {
		return "<nil>"
	}
	return p.Auth.User + "," + p.Auth.Password + "," + p.IPPort
}

// HasAuth returns true if p has auth params.
func (p *ProxyOptions) HasAuth() bool {
	return len(p.Auth.User) > 0 && len(p.Auth.Password) > 0
}

// FullUrl returns the full url with auth.
func (p *ProxyOptions) FullUrl() string {
	if p.HasAuth() {
		// superuser.com/a/532530
		usr := url.QueryEscape(p.Auth.User)
		pwd := url.QueryEscape(p.Auth.Password)
		return p.Scheme + "://" + usr + ":" + pwd + "@" + p.IPPort
	} else if len(p.Auth.User) > 0 {
		usr := url.QueryEscape(p.Auth.User)
		return p.Scheme + "://" + usr + "@" + p.IPPort
	}
	return p.Url()
}

// Url returns the url without auth.
func (p *ProxyOptions) Url() string {
	return p.Scheme + "://" + p.IPPort
}

// AutoMode is a global variable to instruct if backend.Auto proxy
// is in local, remote, or hybrid mode. In local mode, backend.Auto
// uses local proxies (ex: ipn.Exit) only. In remote mode,
// backend.Auto uses remote proxies (ex: RPN).
var AutoMode atomic.Int32

type AutoModeType int32

const (
	// local mode: backend.Auto uses local proxies (ex: ipn.Exit) only.
	AutoModeLocal int32 = iota
	// remote mode: backend.Auto uses remote proxies (ex: RPN) only.
	AutoModeRemote
	// hybrid mode: backend.Auto uses local and remote proxies.
	AutoModeHybrid
)

func (m AutoModeType) String() string {
	switch int32(m) {
	case AutoModeLocal:
		return "local"
	case AutoModeRemote:
		return "remote"
	case AutoModeHybrid:
		return "hybrid"
	default:
		return "unknown"
	}
}

// SetAutoMode sets the global AutoMode variable to m.
// Indicates if backend.Auto proxy is in local, remote, or hybrid mode.
func SetAutoMode(m int32) (prev int32) {
	m = max(m, AutoModeLocal)
	m = min(m, AutoModeHybrid)
	return AutoMode.Swap(m)
}

func AutoModeStr() string {
	return AutoModeType(AutoMode.Load()).String()
}

// backend.Auto must use remote proxies and never use local (ex: ipn.Exit) ones.
func AutoAlwaysRemote() bool {
	return AutoMode.Load() == AutoModeRemote
}

// backend.Auto is effecively not active.
func AutoActive() bool {
	return AutoMode.Load() != AutoModeLocal
}

// AutoDialsParallel is a global variable to instruct ipn.Auto proxy
// to use parallel dialing for all proxies.
var AutoDialsParallel atomic.Bool

// SetAutoDialsParallel puts backend.Auto in parallel-dial mode if y is true.
// That is, backend.Auto will dial all (available) RPN proxies in parallel.
func SetAutoDialsParallel(y bool) (prev bool) {
	return AutoDialsParallel.Swap(y)
}

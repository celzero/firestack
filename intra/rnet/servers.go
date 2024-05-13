// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rnet

import (
	"errors"
	"fmt"
	"sync"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

const (
	// type of services
	SVCSOCKS5 = "svcsocks5" // SOCKS5
	SVCHTTP   = "svchttp"   // HTTP
	PXSOCKS5  = "pxsocks5"  // SOCKS5 with forwarding proxy
	PXHTTP    = "pxhttp"    // HTTP with forwarding proxy

	// status of proxies
	SUP = 0  // svc UP
	SOK = 1  // svc OK
	SKO = -1 // svc not OK
	END = -2 // svc stopped
)

var (
	errNoServer   = errors.New("no such server")
	errSvcRunning = errors.New("service is running")
	errNotUdp     = errors.New("not udp conn")
	errNotTcp     = errors.New("not tcp conn")
	errNoAddr     = errors.New("no address")
	errServerEnd  = errors.New("server stopped")
	errProxyEnd   = errors.New("proxy stopped")
	errNotProxy   = errors.New("not a proxy")
	errBlocked    = errors.New("blocked")

	udptimeoutsec = 5 * 60                    // 5m
	tcptimeoutsec = (2 * 60 * 60) + (40 * 60) // 2h40m
)

// todo: github.com/txthinking/brook/blob/master/pac.go

type Server interface {
	// Sets the proxy as the next hop.
	Hop(p x.Proxy) error
	// ID returns the ID of the server.
	ID() string
	// Start starts the server.
	Start() error
	// Type returns the type of the server.
	Type() string
	// Addr returns the address of the server.
	GetAddr() string
	// Status returns the status of the server.
	Status() int
	// Stop stops the server.
	Stop() error
	// Refresh re-registers the server.
	Refresh() error
}

type Services interface {
	// Add adds a server.
	AddServer(id, url string) (Server, error)
	// Bridge bridges or unbridges server with proxy.
	Bridge(serverid, proxyid string) error
	// Remove removes a server.
	RemoveServer(id string) (ok bool)
	// RemoveAll removes all servers, returns the number removed.
	RemoveAll() (rm int)
	// Get returns a Server.
	GetServer(id string) (Server, error)
	// Stop stops all services, returns the number stopped.
	StopServers() (n int)
	// Refresh re-registers servces and returns a csv of active ones.
	RefreshServers() (active string)
}

var _ Server = (*socks5)(nil)

type services struct {
	sync.RWMutex
	servers  map[string]Server
	proxies  ipn.Proxies
	listener ServerListener
	ctl      protect.Controller
}

func NewServices(proxies ipn.Proxies, ctl protect.Controller, listener ServerListener) Services {
	if listener == nil || ctl == nil {
		return nil
	}
	return &services{
		servers:  make(map[string]Server),
		ctl:      ctl,
		proxies:  proxies,
		listener: listener,
	}
}

func (s *services) AddServer(id, url string) (svc Server, err error) {
	s.RemoveServer(id)

	switch id {
	case SVCSOCKS5, PXSOCKS5:
		svc, err = newSocks5Server(id, url, s.ctl, s.listener)
	case SVCHTTP, PXHTTP:
		svc, err = newHttpServer(id, url, s.ctl, s.listener)
	default:
		return nil, errors.ErrUnsupported
	}

	if err != nil {
		return nil, err
	}

	s.Lock()
	s.servers[id] = svc
	s.Unlock()

	// if the server has a namesake proxy, bridge them
	err = s.Bridge(id, id)

	log.I("svc: add: %s > %s; err? %v", id, url, err)

	return svc, err
}

func (s *services) Bridge(serverid, proxyid string) (err error) {
	svc, err := s.GetServer(serverid)

	if err != nil {
		log.W("svc: bridge: no server %s; err? %v", serverid, err)
		return
	}
	// remove existing bridge, if any
	if len(proxyid) <= 0 {
		err = svc.Hop(nil)
		log.I("svc: bridge: remove all hops for %s; err? %v", serverid, err)
		return
	}

	px, err := s.proxies.ProxyFor(proxyid)
	if err != nil {
		log.W("svc: bridge: no proxy %s for %s; err? %v", proxyid, serverid, err)
		return
	}

	svcstr := fmt.Sprintf("%s/%s [%d] at %s", serverid, svc.Type(), svc.Status(), svc.GetAddr())
	pxstr := fmt.Sprintf("%s/%s [%d] at %s", proxyid, px.Type(), px.Status(), px.GetAddr())

	err = svc.Hop(px)

	log.I("svc: bridge: %s with %s; hop err? %v", svcstr, pxstr, err)

	return
}

func (s *services) RemoveServer(id string) bool {
	if svc, err := s.GetServer(id); err == nil {
		_ = svc.Stop()
		delete(s.servers, id)
		return true
	}
	return false
}

func (s *services) GetServer(id string) (Server, error) {
	s.RLock()
	defer s.RUnlock()

	if svc, ok := s.servers[id]; ok {
		return svc, nil
	}
	return nil, errNoServer
}

func (s *services) StopServers() int {
	s.Lock()
	defer s.Unlock()

	for _, svc := range s.servers {
		_ = svc.Stop()
	}
	return len(s.servers)
}

func (s *services) RefreshServers() string {
	s.Lock()
	defer s.Unlock()

	var csv string
	for _, svc := range s.servers {
		sid := svc.ID()
		if err := svc.Refresh(); err != nil {
			log.W("svc: refresh %s; err: %v", sid, err)
			continue
		}
		if csv == "" {
			csv = sid
		} else {
			csv += "," + sid
		}
	}
	return csv
}

func (s *services) RemoveAll() int {
	n := s.StopServers()

	s.Lock()
	clear(s.servers)
	s.Unlock()

	return n
}

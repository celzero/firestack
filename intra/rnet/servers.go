// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rnet

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

const (
	smmchSize = 256 // some comfortably high number
)

const (
	// type of services
	SVCSOCKS5 = x.SVCSOCKS5
	SVCHTTP   = x.SVCHTTP
	PXSOCKS5  = x.PXSOCKS5
	PXHTTP    = x.PXHTTP

	// status of proxies
	SUP = x.SUP
	SOK = x.SOK
	SKO = x.SKO
	END = x.SOP
)

var (
	errNoServer    = errors.New("svc: no such server")
	errSvcRunning  = errors.New("svc: service is running")
	errNotUdp      = errors.New("svc: not udp conn")
	errNotTcp      = errors.New("svc: not tcp conn")
	errNoAddr      = errors.New("svc: no address")
	errServerEnd   = errors.New("svc: server stopped")
	errProxyEnd    = errors.New("svc: proxy stopped")
	errProxyPaused = errors.New("svc: proxy paused")
	errNotProxy    = errors.New("svc: not a proxy")
	errBlocked     = errors.New("svc: blocked")

	udptimeoutsec = 5 * 60                    // 5m
	tcptimeoutsec = (2 * 60 * 60) + (40 * 60) // 2h40m
)

// todo: github.com/txthinking/brook/blob/master/pac.go

type Server x.Server

type Services x.Services

type ServerListener x.ServerListener

var _ Services = (*services)(nil)
var _ Server = (*httpx)(nil)
var _ Server = (*socks5)(nil)

type services struct {
	sync.RWMutex
	servers  map[string]Server
	proxies  ipn.Proxies
	listener ServerListener
	ctl      protect.Controller

	ctx   context.Context
	smmch chan *ServerSummary // channel for server summaries
}

func NewServices(pctx context.Context, proxies ipn.Proxies, ctl protect.Controller, listener ServerListener) *services {
	if listener == nil || ctl == nil {
		return nil
	}
	svc := &services{
		ctx:      pctx,
		servers:  make(map[string]Server),
		ctl:      ctl,
		proxies:  proxies,
		listener: listener,
		smmch:    make(chan *ServerSummary, smmchSize),
	}
	context.AfterFunc(pctx, svc.stopServers)
	core.Gx("svc.smm", svc.processSummaries)
	return svc
}

func (s *services) AddServer(typ, id, url string) (svc x.Server, err error) {
	s.RemoveServer(id)

	switch typ {
	case SVCSOCKS5, PXSOCKS5:
		svc, err = newSocks5Server(id, url, s.ctl, s.listener, s.smmch)
	case SVCHTTP, PXHTTP:
		svc, err = newHttpServer(id, url, s.ctl, s.listener, s.smmch)
	default:
		err = errors.ErrUnsupported
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

func (s *services) GetServer(id string) (x.Server, error) {
	s.RLock()
	defer s.RUnlock()

	if svc, ok := s.servers[id]; ok {
		return svc, nil
	}
	return nil, errNoServer
}

func (s *services) stopServers() {
	s.Lock()
	defer s.Unlock()

	n := len(s.servers)
	for _, svc := range s.servers {
		_ = svc.Stop()
	}
	log.I("svc: stopped servers: %d", n)
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

func (s *services) RemoveAll() {
	s.stopServers()

	s.Lock()
	clear(s.servers)
	s.Unlock()
}

// queueSummary queues a server summary to be sent to the listener; thread-safe.
// non-blocking; drops the summary if the channel is full or the context is done.
func (s *services) queueSummary(sum *ServerSummary) {
	if sum == nil {
		return
	}
	select {
	case <-s.ctx.Done():
		if log.Debug {
			log.D("svc: queueSummary: end: %s", sum)
		}
	default:
		select {
		case <-s.ctx.Done():
		case s.smmch <- sum:
		default:
			log.W("svc: queueSummary: dropped: %s", sum)
		}
	}
}

// processSummaries reads summaries from smmch and sends them to the listener.
func (s *services) processSummaries() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case sum, ok := <-s.smmch:
			if !ok {
				return // channel closed
			}
			if sum != nil {
				s.sendSummary(sum)
			}
		}
	}
}

// sendSummary sends a summary to the listener; thread-safe.
func (s *services) sendSummary(sum *ServerSummary) {
	// sleep a bit to avoid scenario where kotlin-land
	// hasn't yet had the chance to persist info about
	// this conn (cid) to meaninfully process its summary
	const after = 50 * time.Millisecond
	time.Sleep(after)

	if log.Verbose {
		log.VV("svc: sendNotif: %s", sum)
	}
	s.listener.OnSvcComplete(sum.ServerSummary)
}

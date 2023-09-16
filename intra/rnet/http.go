// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rnet

import (
	"net/http"
	"net/url"
	"time"

	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	tx "github.com/elazarl/goproxy"
)

type httpx struct {
	*tx.ProxyHttpServer
	id     string
	host   string
	svc    *http.Server
	hdl    *httpxhandler
	usetls bool
	status int
}

type httpxhandler struct {
	*AuthHandler
	px ipn.Proxy
}

func newHttpServer(id, x string, ctl protect.Controller) (Server, error) {
	var host string
	var usr string
	var pwd string

	// ex: "http://u:p@host:8080"; "http://u:p@:8080"; "http://:8080"; "http://host"
	u, err := url.Parse(x)
	if err != nil {
		return nil, err
	}
	host = u.Host      // host
	if u.User != nil { // usr, pwd
		usr = u.User.Username()    // may be empty
		pwd, _ = u.User.Password() // may be empty
	}
	dialer := protect.MakeNsDialer(ctl)
	hdl := &httpxhandler{
		AuthHandler: &AuthHandler{usr: usr, pwd: pwd},
	}
	hproxy := tx.NewProxyHttpServer()
	hproxy.Logger = log.Glogger
	hproxy.Tr = &http.Transport{
		Dial:                  dialer.Dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	// todo: dial to connect endpoint as defined by the underlying network or the OS
	hproxy.ConnectDial = nil
	hproxy.ConnectDialWithReq = nil

	svc := &http.Server{Addr: host, Handler: hproxy}
	usetls := u.Scheme == "https"
	hasauth := len(usr) > 0 || len(pwd) > 0
	if hasauth {
		hproxy.OnRequest(hdl.notok()).HandleConnectFunc(hdl.denyConnect)
		hproxy.OnRequest(hdl.notok()).DoFunc(hdl.denyRequest)
	}

	log.I("svchttp: new %s listening at %s; tls? %t / auth? %t", id, host, usetls, hasauth)
	return &httpx{
		ProxyHttpServer: hproxy,
		id:              id,
		usetls:          usetls,
		host:            host,
		hdl:             hdl,
		svc:             svc,
		status:          SOK,
	}, nil
}

type AuthHandler struct {
	usr string
	pwd string
}

func (au *AuthHandler) notok() tx.ReqConditionFunc {
	return func(req *http.Request, ctx *tx.ProxyCtx) bool {
		if len(au.usr) == 0 && len(au.pwd) == 0 {
			return false // no auth; do not handle
		}
		u, p, ok := req.BasicAuth()
		return !ok || u != au.usr || p != au.pwd // handle if match
	}
}

func (au *AuthHandler) denyConnect(host string, ctx *tx.ProxyCtx) (*tx.ConnectAction, string) {
	act := &tx.ConnectAction{Action: tx.ConnectProxyAuthHijack, TLSConfig: tx.TLSConfigFromCA(&tx.GoproxyCa)}
	return act, ""
}

func (au *AuthHandler) denyRequest(req *http.Request, ctx *tx.ProxyCtx) (*http.Request, *http.Response) {
	return req, tx.NewResponse(req, tx.ContentTypeText, http.StatusUnauthorized, "Unauthorized")
}

func (h *httpx) Hop(p ipn.Proxy) error {
	if p == nil {
		h.hdl.px = nil
		return nil
	}
	if h.status == END {
		log.D("svchttp: hop: %s not running", h.ID())
		return errServerEnd
	}
	h.hdl.px = p
	h.ProxyHttpServer.Tr.Dial = ipn.AsDialFn(p)
	log.D("svchttp: hop: %s set to %s", h.ID(), p.GetAddr())
	return nil
}

func (h *httpx) Start() error {
	if h.status != END {
		return errSvcRunning
	}
	h.status = SOK
	go func() {
		if h.usetls {
			h.status = END
			log.E("svchttp: %s cannot start; tls is unimplemented", h.ID())
			return
		}
		err := h.svc.ListenAndServe()
		log.I("svchttp: %s exited; err? %v", h.ID(), err)
		h.status = END
	}()
	log.I("svchttp: %s started %s", h.ID(), h.GetAddr())
	return nil
}

func (h *httpx) Stop() error {
	err := h.svc.Close()
	// err := h.svc.Shutdown(context.Background())
	h.status = END
	log.I("svchttp: %s stopped; err? %v", h.ID(), err)
	return err
}

func (h *httpx) Refresh() error {
	h.status = SOK
	err1 := h.Stop()
	time.Sleep(3 * time.Second) // arbitrary wait
	err2 := h.Start()

	log.I("svchttp: %s refreshed; errs? %v; %v", h.ID(), err1, err2)

	if err2 != nil {
		return err2
	}
	return err1
}

func (h *httpx) ID() string {
	return h.id
}

func (h *httpx) GetAddr() string {
	px := h.hdl.px
	if px != nil {
		return px.GetAddr()
	}
	return h.host
}

func (h *httpx) Status() int {
	return h.status
}

func (h *httpx) Type() string {
	px := h.hdl.px
	if px != nil {
		return PXHTTP
	}
	return SVCHTTP
}

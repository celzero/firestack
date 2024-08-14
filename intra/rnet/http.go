// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	tx "github.com/elazarl/goproxy"
)

type dialContextFn func(context.Context, string, string) (net.Conn, error)

type httpx struct {
	id       string
	host     string
	dialer   *net.Dialer
	svc      *http.Server
	hdl      *httpxhandle
	listener ServerListener
	usetls   bool

	// mutable fields below
	sync.Mutex          // protects tx.ProxyHttpServer
	*tx.ProxyHttpServer // changed by Hop()

	status *core.Volatile[int] // status of the server
}

type httpxhandle struct {
	*AuthHandle
	px *core.Volatile[ipn.Proxy]
}

func newHttpServer(id, x string, ctl protect.Controller, listener ServerListener) (*httpx, error) {
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
	dialer := protect.MakeNsDialer(id, ctl)
	hdl := &httpxhandle{
		AuthHandle: &AuthHandle{usr: usr, pwd: pwd},
		px:         core.NewZeroVolatile[ipn.Proxy](),
	}
	hproxy := tx.NewProxyHttpServer()
	hproxy.Logger = log.Glogger
	hproxy.Tr = &http.Transport{
		DialContext:           dialer.DialContext, // overriden by Hop()
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	// todo: dial to connect endpoint as defined by the underlying network or the OS
	hproxy.ConnectDial = nil
	hproxy.ConnectDialWithReq = nil

	svc := &http.Server{Addr: host, Handler: hproxy, ReadHeaderTimeout: 10 * time.Second}
	usetls := u.Scheme == "https"
	hasauth := len(usr) > 0 || len(pwd) > 0
	if hasauth {
		// todo: listener with summary and route
		hproxy.OnRequest(hdl.notok()).HandleConnectFunc(hdl.denyConnect)
		hproxy.OnRequest(hdl.notok()).DoFunc(hdl.denyRequest)
	}

	log.I("svchttp: new %s listening at %s; tls? %t / auth? %t", id, host, usetls, hasauth)
	hx := &httpx{
		ProxyHttpServer: hproxy,
		id:              id,
		usetls:          usetls,
		host:            host,
		dialer:          dialer,
		hdl:             hdl,
		svc:             svc,
		listener:        listener,
		status:          core.NewVolatile(SOK),
	}
	hproxy.OnRequest().HandleConnectFunc(hx.routeConnect)
	hproxy.OnRequest().DoFunc(hx.route)
	hproxy.OnResponse().DoFunc(hx.summarize)

	return hx, nil
}

type AuthHandle struct {
	usr string
	pwd string
}

func (au *AuthHandle) notok() tx.ReqConditionFunc {
	return func(req *http.Request, ctx *tx.ProxyCtx) bool {
		if len(au.usr) == 0 && len(au.pwd) == 0 {
			return false // no auth; do not handle
		}
		u, p, ok := req.BasicAuth()
		return !ok || u != au.usr || p != au.pwd // handle if match
	}
}

func (au *AuthHandle) denyConnect(host string, ctx *tx.ProxyCtx) (*tx.ConnectAction, string) {
	act := &tx.ConnectAction{Action: tx.ConnectProxyAuthHijack, TLSConfig: tx.TLSConfigFromCA(&tx.GoproxyCa)}
	return act, host // "host" is unused when action is ConnectProxyAuthHijack
}

func (au *AuthHandle) denyRequest(req *http.Request, ctx *tx.ProxyCtx) (*http.Request, *http.Response) {
	return req, tx.NewResponse(req, tx.ContentTypeText, http.StatusUnauthorized, "Unauthorized")
}

// using ctx.UserData to store summary
// github.com/elazarl/goproxy/blob/2592e75ae0/examples/goproxy-httpdump/httpdump.go#L254
// and counting bytes via a wrapped read-writer
// github.com/elazarl/goproxy/blob/2592e75ae0/examples/goproxy-stats/main.go#L61
func (h *httpx) route(req *http.Request, ctx *tx.ProxyCtx) (*http.Request, *http.Response) {
	src := req.RemoteAddr
	sid := h.id
	pid := h.pid()
	tab := h.listener.Route(sid, pid, "tcp", src, req.Host)
	log.D("svchttp: route: tab(%v) id(%s) p(%s) src(%s) dst(%s)", tab, h.id, pid, src, req.Host)
	if tab.Block {
		return req, tx.NewResponse(req, tx.ContentTypeText, http.StatusForbidden, "Forbidden")
	}
	ctx.UserData = serverSummary(h.Type(), sid, pid, tab.CID)
	return req, nil
}

func (h *httpx) summarize(res *http.Response, ctx *tx.ProxyCtx) *http.Response {
	req := res.Request
	if ctx.UserData == nil {
		if req != nil {
			log.W("svchttp: summarize for %s<-%s missing; n: %d", req.Host, req.RemoteAddr, req.ContentLength)
		} else {
			log.W("svchttp: summarize missing")
		}
	}
	ssu, ok := ctx.UserData.(*ServerSummary)
	if !ok {
		log.W("svchttp: summarize: invalid userdata %v", ctx.UserData)
		return res
	}
	ssu.Rx = int(res.ContentLength)
	if req != nil {
		ssu.Tx = int(req.ContentLength)
	}
	ssu.done(errNop)
	go h.listener.OnComplete(ssu)
	return res
}

func (h *httpx) routeConnect(host string, ctx *tx.ProxyCtx) (*tx.ConnectAction, string) {
	src := h.svc.Addr
	dst := ctx.Req.Host
	sid := h.id
	pid := h.pid()
	tab := h.listener.Route(sid, pid, "tcp", src, host)
	log.D("svchttp: routeConnect: tab(%v) id(%s) p(%s) src(%s) dst(%s)", tab, h.id, pid, src, dst)
	if tab.Block {
		return tx.RejectConnect, host
	}
	ctx.UserData = serverSummary(h.Type(), sid, pid, tab.CID)
	hijackact := &tx.ConnectAction{Action: tx.ConnectHijack, Hijack: h.hijackConnect}
	return hijackact, host
}

// from: https://github.com/elazarl/goproxy/blob/2592e75ae0/https.go#L126-L154
func (h *httpx) hijackConnect(req *http.Request, client net.Conn, ctx *tx.ProxyCtx) {
	ssu, _ := ctx.UserData.(*ServerSummary)
	host := req.Host
	addr, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		log.W("svchttp: hijackConnect: host(%s) not valid addr/port err %v", host, err)
	} else if len(port) <= 0 {
		host = net.JoinHostPort(addr, "80")
	}
	target, err := h.Tr.DialContext(context.Background(), "tcp", host)
	if err != nil {
		http502(client, err, ssu)
		return
	}
	log.D("Accepting CONNECT to %s; cid: %s", host, ssu.CID)
	n, err := client.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		log.W("svchttp: hijackConnect: failed client write (%d); err %v", n, err)
		http502(client, err, ssu)
		return
	}

	go func() {
		wg := &sync.WaitGroup{}
		wg.Add(2)

		dst, ok1 := target.(*net.TCPConn)
		src, ok2 := client.(*net.TCPConn)
		if ok1 && ok2 {
			go pipetcp(dst, src, ssu, wg)
			go pipetcp(src, dst, ssu, wg)
			wg.Wait()
		} else {
			go pipeconn(target, client, ssu, wg)
			go pipeconn(client, target, ssu, wg)
			wg.Wait()
			clos(client, target)
		}
		h.listener.OnComplete(ssu)
	}()
}

func clos(cs ...io.Closer) {
	core.Close(cs...)
}

func http502(w io.WriteCloser, err1 error, ssu *ServerSummary) {
	_, err2 := io.WriteString(w, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
	err3 := w.Close()
	if ssu != nil {
		ssu.done(err1, err2, err3)
	}
	log.D("svchttp: http502: done http-connect; errs? %v", errors.Join(err1, err2, err3))
}

func pipeconn(dst net.Conn, src net.Conn, ssu *ServerSummary, wg *sync.WaitGroup) {
	var err error
	defer wg.Done()
	defer ssu.done(err) // done handles nil ssu

	_, err = core.Pipe(dst, src)
	log.D("svchttp: pipeconn: done; err src(%s) -> dst(%s); err? %v", src.RemoteAddr(), dst.RemoteAddr(), err)
}

func pipetcp(dst, src *net.TCPConn, ssu *ServerSummary, wg *sync.WaitGroup) {
	_, err1 := core.Pipe(dst, src)
	log.D("svchttp: pipetcp: done; src (%s) -> dst(%s); err? %v", src.RemoteAddr(), dst.RemoteAddr(), err1)
	err2 := dst.CloseWrite()
	err3 := src.CloseRead()
	if ssu != nil {
		ssu.done(err1, err2, err3)
	}
	wg.Done()
}

func (h *httpx) Hop(p x.Proxy) error {
	if h.status.Load() == END {
		log.D("svchttp: hop: %s not running", h.ID())
		return errServerEnd
	}

	dialer := h.dialer.DialContext
	if p == nil || core.IsNil(p) {
		h.hdl.px.Store(nil) // clear
		// h.ProxyHttpServer.Tr.DialContext = h.dialer.DialContext
	} else if pp, ok := p.(ipn.Proxy); ok {
		h.hdl.px.Store(pp)
		dialer = pp.Dialer().DialContext
	} else {
		log.E("svchttp: hop: %s; failed: %T not ipn.Proxy", h.ID(), p)
		return errNotProxy
	}

	log.D("svchttp: hop: %s over proxy? %t via %s", h.ID(), p != nil, h.GetAddr())

	h.swap(dialer)
	return nil
}

func (h *httpx) swap(f dialContextFn) {
	h.Lock()
	defer h.Unlock()
	// todo: reads are not synchronized!
	h.ProxyHttpServer.Tr.DialContext = f
}

func (h *httpx) Start() error {
	if h.status.Load() == END {
		return errSvcRunning
	}
	h.status.Store(SOK)
	go func() {
		if h.usetls {
			h.status.Store(END)
			log.E("svchttp: %s cannot start; tls is unimplemented", h.ID())
			return
		}
		err := h.svc.ListenAndServe()
		log.I("svchttp: %s exited; err? %v", h.ID(), err)
		h.status.Store(END)
	}()
	log.I("svchttp: %s started %s", h.ID(), h.GetAddr())
	return nil
}

func (h *httpx) Stop() error {
	err := h.svc.Close()
	// err := h.svc.Shutdown(context.Background())
	h.status.Store(END)
	log.I("svchttp: %s stopped; err? %v", h.ID(), err)
	return err
}

func (h *httpx) Refresh() error {
	err1 := h.Stop()
	time.Sleep(3 * time.Second) // arbitrary wait
	err2 := h.Start()

	log.I("svchttp: %s refreshed; errs? %v; %v", h.ID(), err1, err2)

	if err2 != nil {
		return err2
	}
	return err1
}

func (h *httpx) pid() (x string) {

	if px := h.hdl.px.Load(); px != nil && core.IsNotNil(px) {
		x = px.ID()
	}
	return
}

func (h *httpx) ID() string {
	return h.id
}

func (h *httpx) GetAddr() string {
	if px := h.hdl.px.Load(); px != nil && core.IsNotNil(px) {
		return px.GetAddr()
	}
	return h.host
}

func (h *httpx) Status() int {
	return h.status.Load()
}

func (h *httpx) Type() string {
	if px := h.hdl.px.Load(); px != nil && core.IsNotNil(px) {
		return PXHTTP // proxied
	}
	return SVCHTTP // direct
}

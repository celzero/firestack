// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (c) 2021 Snawoot

package ipn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"time"

	se "github.com/Snawoot/opera-proxy/seclient"
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/seasy"
	"github.com/celzero/firestack/intra/ipn/warp"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/noql-net/certpool"
	"golang.org/x/net/proxy"
)

// from: https://github.com/Snawoot/opera-proxy/blob/27b3da3004/upstream.go
// reddit.com/r/operabrowser/comments/18jnxbt/is_opera_a_spyware

const (
	protoH1       = "HTTP/1.1"
	methodConnect = "CONNECT"
	hdrHost       = "Host"
	hdrProxyAuthz = "Proxy-Authorization"
	seHostname    = "sec-tunnel.com"
)

const fourHours = 4 * time.Hour

// read byte by byte until crlf to avoid reading
// more than just the request line:
// github.com/saucelabs/forwarder/issues/616
const readonebyte = true

// end of request line
var crlfcrlf = []byte("\r\n\r\n")

var (
	errMissingSEClient = errors.New("se: missing client")
	errSEProxyBlocks   = errors.New("se: remote blocked request")
	errSEProxyResponse = errors.New("se: bad response")
	errSENoEndpoints   = errors.New("se: no endpoints")
	errSEOnlyTcp       = errors.New("se: supports only tcp")
)

type authFn func() (cred string)
type dialFn func(network, addr string) (net.Conn, error)

type seproxy struct {
	NoFwd
	NoDNS
	SkipRefresh
	ProtoAgnostic
	GW

	warp.RpnStateless
	warp.RpnCountryless

	done      context.CancelFunc
	sec       *seasy.SEApi
	addrs     []netip.AddrPort
	outbounds []proxy.Dialer
	px        ProxyProvider
	viaID     *core.Volatile[string]
	via       *core.WeakRef[Proxy]

	lastRefresh *core.Volatile[time.Time]
	status      *core.Volatile[int]
}

type sedialer struct {
	addr, sni string
	auth      authFn
	cert      *x509.Certificate
	dialer    dialFn
}

var _ RpnAcc = (*seproxy)(nil)
var _ Proxy = (*seproxy)(nil)
var _ proxy.Dialer = (*sedialer)(nil)

// NewSEasyProxy returns a new seproxy.
func NewSEasyProxy(ctx context.Context, c protect.Controller, px ProxyProvider, sec *seasy.SEApi) (*seproxy, error) {
	if sec == nil {
		return nil, errMissingSEClient
	}

	ctx, done := context.WithCancel(ctx)
	if _, err := sec.Start(ctx); err != nil {
		done()
		return nil, err
	}

	endpoints := sec.Endpoints()
	if len(endpoints) <= 0 { // unlikely
		done()
		return nil, errSENoEndpoints
	}

	authfn := func() string {
		return headerBasicAuth(sec.GetProxyCredentials())
	}

	var missingcert *x509.Certificate
	if der, _ := pem.Decode([]byte(seasy.MISSING_CHAIN_CERT)); der != nil {
		missingcert, _ = x509.ParseCertificate(der.Bytes)
	}

	now := time.Now()
	if missingcert != nil && missingcert.NotAfter.Before(now) {
		log.E("proxy: se: missing cert expired on %s (wall: %s)",
			missingcert.NotAfter, now)
		missingcert = nil
	}

	sep := &seproxy{
		done:        done,
		sec:         sec,
		addrs:       sec.Addrs(),
		px:          px,
		viaID:       core.NewZeroVolatile[string](),
		lastRefresh: core.NewVolatile(now),
		status:      core.NewVolatile(TUP),
	}
	var err error
	sep.via, err = core.NewWeakRef(sep.viafor, viaok)
	if err != nil { // unlikely
		return nil, err
	}

	outbound := protect.MakeNsRDial(RpnSE, ctx, c)
	dialfn := func(network, addr string) (c net.Conn, err error) {
		who := sep.ID()
		if usevia(sep.viaID) {
			if v, vok := sep.via.Get(); vok {
				who = idstr(v)
				c, err = v.Dial(network, addr)
			} else {
				err = errNoHop
				if removeViaOnErrors {
					sep.Hop(nil, false /*dryrun*/)
				}
				log.W("proxy: se: via(%s@%s) failing...", idstr(v), idhandle(v))
			}
		} else {
			c, err = outbound.Dial(network, addr)
		}
		logei(err)("proxy: se: %s dial(%s) from %s => %s (via %s); err? %v",
			sep.ID(), network, sep.GetAddr(), addr, who, err)
		return c, err
	}

	seds := make([]proxy.Dialer, 0)
	for _, ep := range endpoints {
		seds = append(seds, newSEDialer(ep, authfn, missingcert, dialfn))
	}
	sep.outbounds = seds

	log.I("proxy: se: started with %d endpoints %v", len(seds), endpoints)

	return sep, nil
}

func newSEDialer(ep se.SEIPEntry, auth authFn, x *x509.Certificate, d dialFn) *sedialer {
	return &sedialer{
		addr:   ep.NetAddr(),
		sni:    fmt.Sprintf("%s0.%s", ep.Geo.Country, seHostname),
		auth:   auth,
		cert:   x,
		dialer: d,
	}
}

// Dial implements proxy.Dialer.
func (sed *sedialer) Dial(network, dest string) (conn net.Conn, err error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errSEOnlyTcp
	}

	conn, err = sed.dialer(network, sed.addr)

	defer func() {
		closeOnErr(err, conn)
	}()

	if err != nil {
		log.E("se: %s => %s err outbound: %v", sed.addr, dest, err)
		return conn, err
	}

	// Verify peer cert chain with missing cert ourselves
	conn = tls.Client(conn, &tls.Config{
		ServerName:         "", // avoid sending sni
		InsecureSkipVerify: true,
		VerifyConnection:   sed.tlsVerify,
	})

	req := &http.Request{
		Method: methodConnect,
		Proto:  protoH1,
		// major.minor must be set to 1.1
		// go.dev/play/p/aPrGA91cmeW
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL:        &url.URL{Opaque: dest},
		Host:       dest,
		Header: http.Header{
			hdrHost: []string{dest},
		},
	}
	// auth is refreshed async; never cache it
	req.Header.Set(hdrProxyAuthz, sed.auth())

	res, err := roundtrip(conn, req)

	if err != nil || res == nil {
		log.E("se: %s => %s err reading res: %v", sed.addr, dest, core.OneErr(err, errNoProxyResponse))
		return conn, err
	}

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusForbidden &&
			res.Header.Get("X-Hola-Error") == "Forbidden Host" {
			return conn, errSEProxyBlocks
		}
		log.E("se: %s bad proxy response: %s => %s", sed.addr, dest, res.Status)
		return conn, errSEProxyResponse
	}

	log.I("se: %s connected to %s (via %s)", sed.sni, dest, sed.addr)

	return conn, nil
}

// github.com/Snawoot/opera-proxy/blob/27b3da3004/upstream.go#L129
func (sed *sedialer) tlsVerify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) < 2 {
		return nil // no intermediates
	}
	// todo: return nil if sed.cert is nil?
	opts := x509.VerifyOptions{
		DNSName:       sed.sni,
		Intermediates: x509.NewCertPool(),
		Roots:         certpool.Roots(),
	}
	linkNeeded := false
	for _, cert := range cs.PeerCertificates[1:] {
		// add all peer certs except the leaf
		opts.Intermediates.AddCert(cert)
		// add missing cert if it is not already in the chain
		if sed.cert != nil && !linkNeeded {
			linkNeeded = bytes.Equal(cert.AuthorityKeyId, sed.cert.SubjectKeyId)
		}
	}
	// add missing cert if it's needed in the chain
	if linkNeeded {
		opts.Intermediates.AddCert(sed.cert)
	}

	chain, err := cs.PeerCertificates[0].Verify(opts)
	logev(err)("se: %s tls verify (w missing cert? %t); len(chain): %d; err? %v",
		sed.sni, linkNeeded, len(chain), err)
	return err
}

func roundtrip(conn net.Conn, req *http.Request) (*http.Response, error) {
	if readonebyte {
		rawreq, err := httputil.DumpRequest(req, false)
		if err != nil {
			return nil, fmt.Errorf("se: dump req err %v", err)
		}
		_, err = conn.Write(rawreq)
		if err != nil {
			return nil, fmt.Errorf("se: write req err %v", err)
		}

		acc := new(bytes.Buffer) // accumulator
		b := make([]byte, 1)     // one byte at a time
		for {
			n, err := conn.Read(b)
			if n < 1 && err == nil {
				continue
			}
			acc.Write(b) // acc until crlfcrlf
			reqline := acc.Bytes()
			tot := len(reqline)
			if tot < len(crlfcrlf) {
				continue
			}
			// check if last 4 bytes are crlfcrlf
			if bytes.Equal(reqline[tot-4:], crlfcrlf) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("se: read req %d err %v", tot, err)
			}
		}
		return http.ReadResponse(bufio.NewReader(acc), req)
	} else {
		if err := req.Write(conn); err != nil {
			return nil, fmt.Errorf("se: write2 req err %v", err)
		}
		return http.ReadResponse(bufio.NewReader(conn), req)
	}
}

func headerBasicAuth(u, pwd string) string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(u+":"+pwd))
}

func (h *seproxy) maybeRefresh() {
	now := time.Now()
	if then := h.lastRefresh.Load(); now.Sub(then) > fourHours {
		if h.lastRefresh.Cas(then, now) {
			core.Go("se.refresh", h.sec.Refresh)
		}
	}
}

// Handle implements Proxy.
func (h *seproxy) Handle() uintptr {
	return core.Loc(h)
}

// ID implements Proxy.
func (*seproxy) ID() string {
	return RpnSE
}

// Type implements Proxy.
func (*seproxy) Type() string {
	return HTTP1
}

// Router implements Proxy.
func (h *seproxy) Router() x.Router {
	return h
}

// Dial implements Proxy.
func (h *seproxy) Dial(network, addr string) (protect.Conn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	defer h.maybeRefresh()

	c, err := dialers.ProxyDials(h.outbounds, network, addr)
	defer localDialStatus(h.status, err)

	if err != nil {
		// shuffle outbounds to avoid always trying the same one
		h.outbounds = shuffle(h.outbounds)
	}
	return c, err
}

// DialBind implements Proxy.
func (d *seproxy) DialBind(network, local, remote string) (net.Conn, error) {
	log.D("se: dialbind(%s) from %s to %s not supported", network, local, remote)
	// TODO: error instead?
	return d.Dial(network, remote)
}

// Dialer implements Proxy.
func (d *seproxy) Dialer() protect.RDialer {
	return d
}

// Reaches implements x.Router.
func (h *seproxy) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

func (h *seproxy) viafor() *Proxy {
	return viafor(h.ID(), h.viaID.Load(), h.px)
}

func (h *seproxy) swapVia(new Proxy) Proxy {
	return swapVia(h.ID(), new, h.viaID, h.via)
}

// Hop implements Proxy.
func (h *seproxy) Hop(p Proxy, dryrun bool) error {
	if p == nil {
		if !dryrun {
			old := h.swapVia(nil)
			log.I("se: hop(%s@%s) removed", idstr(old), idhandle(old))
		}
		return nil
	}
	if p.Status() == END {
		return errProxyStopped
	}

	if !dryrun {
		old := h.swapVia(p)
		log.I("se: hop(%s@%s) => %s@%s",
			idstr(old), idhandle(old), idstr(p), idhandle(p))
	}
	return nil
}

// Via implements x.Router.
func (h *seproxy) Via() (x.Proxy, error) {
	if v := h.via.Load(); v != nil {
		return v, nil
	}
	return nil, nil
}

// GetAddr implements Proxy.
func (h *seproxy) GetAddr() string {
	if len(h.addrs) <= 0 {
		return ""
	}
	n := rand.IntN(len(h.addrs))
	return h.addrs[n].String()
}

// Status implements Proxy.
func (h *seproxy) Status() int {
	return h.status.Load()
}

// Stop implements Proxy.
func (h *seproxy) Stop() error {
	h.status.Store(END)
	h.done()
	log.I("proxy: se: stopped")
	return nil
}

// Who implements x.RpnAcc.
func (h *seproxy) Who() string {
	if h == nil || h.sec == nil {
		return ""
	}
	return h.sec.AssignedDeviceID
}

// Provider implements RpnAcc.
func (*seproxy) ProviderID() string { return RpnSE }

// Created implements x.RpnAcc.
func (h *seproxy) Created() int64 {
	return h.lastRefresh.Load().UnixMilli()
}

// Expires implements x.RpnAcc.
func (h *seproxy) Expires() int64 {
	return h.lastRefresh.Load().Add(fourHours).UnixMilli()
}

func closeOnErr(err error, c io.Closer) {
	if err != nil {
		core.Close(c)
	}
}

func shuffle[T any](a []T) []T {
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
	return a
}

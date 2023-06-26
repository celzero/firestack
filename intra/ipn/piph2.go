// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/core/ipmap"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/split"
	"golang.org/x/net/http2"
)

const (
	h2only                              = true
	tlsHandshakeTimeout   time.Duration = 10 * time.Second
	responseHeaderTimeout time.Duration = 10 * time.Second
)

type piph2 struct {
	Proxy
	id       string      // some unique identifier
	url      string      // h2 proxy url
	hostname string      // h2 proxy hostname
	port     int         // h2 proxy port
	ips      ipmap.IPMap // h2 proxy working ips
	token    string      // hex, client token
	sig      string      // hex, authorizer signed client token
	client   http.Client // h2 client, see h2only
	dialer   *net.Dialer // h2 dialer
	status   int         // proxy status: TOK, TKO, END
}

type pipconn struct {
	core.TCPConn
	id    string               // some identifier
	rch   <-chan io.ReadCloser // reader provider
	ok    bool                 // r is ok to read from
	r     io.ReadCloser        // reader, nil until ok is true
	rmu   *sync.Mutex          // rmu protects r
	w     io.WriteCloser       // writer
	wmu   *sync.Mutex          // wmu protects w
	laddr net.Addr             // local address, may be nil
	raddr net.Addr             // remote address
}

func (c *pipconn) Read(b []byte) (int, error) {
	log.V("piph2: read(%v/%s) waiting?(%t)", len(b), c.id, c.ok)
	if !c.ok {
		c.r = <-c.rch // nil on error
		c.ok = true
	}
	if c.r == nil {
		log.E("piph2: read(%v/%s) not ok", len(b), c.id)
		return 0, io.EOF
	}
	// github.com/posener/h2conn/blob/13e7df33ed1/conn.go
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.r.Read(b)
}

func (c *pipconn) Write(b []byte) (int, error) {
	log.V("piph2: write(%v/%s) read-waiting?(%t)", len(b), c.id, c.ok)
	if c.w == nil {
		log.E("piph2: write(%v/%s) not ok", len(b), c.id)
		return 0, io.EOF
	}
	// github.com/posener/h2conn/blob/13e7df33ed1/conn.go
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.w.Write(b)
}

func (c *pipconn) Close() (err error) {
	log.D("piph2: close(%s); waiting?(%t)", c.id, c.ok)
	c.CloseRead()
	return c.CloseWrite()
}

func (c *pipconn) CloseRead() error {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if c.r != nil {
		return c.r.Close()
	}
	return nil
}

func (c *pipconn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if c.w != nil {
		return c.w.Close()
	}
	return nil
}

func (c *pipconn) LocalAddr() net.Addr           { return c.laddr }
func (c *pipconn) RemoteAddr() net.Addr          { return c.raddr }
func (c *pipconn) SetDeadline(t time.Time) error { return nil }
func SetReadDeadline(t time.Time) error          { return nil }
func SetWriteDeadline(t time.Time) error         { return nil }

func (t *piph2) dialtls(network, addr string, cfg *tls.Config) (net.Conn, error) {
	rawConn, err := t.dial(network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if cfg == nil {
		cfg = &tls.Config{ServerName: hostname}
	} else if cfg.ServerName == "" {
		// If no ServerName is set, infer the ServerName
		// from the hostname we're connecting to.
		// Make a copy to avoid polluting argument or default.
		c := cfg.Clone()
		c.ServerName = hostname
		cfg = c
	}

	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(context.Background()); err != nil {
		log.D("piph2: dialtls(%s) handshake error: %v", addr, err)
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

func (t *piph2) dial(network, addr string) (net.Conn, error) {
	log.D("piph2: dialing %s", addr)
	domain, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	tcpaddr := func(ip net.IP) *net.TCPAddr {
		return &net.TCPAddr{IP: ip, Port: port}
	}

	var conn net.Conn
	ips := t.ips.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed != nil {
		if conn, err = split.DialWithSplitRetry(t.dialer, tcpaddr(confirmed), nil); err == nil {
			log.I("piph2: confirmed IP %s worked", confirmed.String())
			return conn, nil
		}
		log.D("piph2: confirmed IP %s failed with err %v", confirmed.String(), err)
		ips.Disconfirm(confirmed)
	}

	log.D("piph2: trying all IPs")
	for _, ip := range ips.GetAll() {
		if ip.Equal(confirmed) {
			// Don't try this IP twice.
			continue
		}
		if conn, err = split.DialWithSplitRetry(t.dialer, tcpaddr(ip), nil); err == nil {
			log.I("piph2: found working IP: %s", ip.String())
			return conn, nil
		}
	}
	return nil, err
}

func NewPipProxy(id string, ctl protect.Controller, po *settings.ProxyOptions) (Proxy, error) {
	parsedurl, err := url.Parse(po.Url())
	if err != nil {
		return nil, err
	}
	// may be "piph2"
	if parsedurl.Scheme != "https" {
		parsedurl.Scheme = "https"
	}
	portStr := parsedurl.Port()
	var port int
	if len(portStr) > 0 {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
	} else {
		port = 443
	}

	dialer := protect.MakeNsDialer(ctl)
	t := &piph2{
		id:       id,
		url:      parsedurl.String(),
		hostname: parsedurl.Hostname(),
		port:     port,
		dialer:   dialer,
		token:    po.Auth.User,
		sig:      po.Auth.Password,
		ips:      ipmap.NewIPMap(dialer.Resolver),
		status:   TOK,
	}

	ipset := t.ips.Of(t.hostname, po.Addrs) // po.Addrs may be nil or empty
	if ipset.Empty() {
		// IPs instead resolved just-in-time with ipmap.Get in transport.dial
		log.W("piph2: zero bootstrap ips %s", t.hostname)
	}

	// Override the dial function.
	// h2 is duplex: github.com/golang/go/issues/19653#issuecomment-341539160
	if h2only {
		t.client.Transport = &http2.Transport{
			DialTLS: t.dialtls,
		}
	} else {
		t.client.Transport = &http.Transport{
			Dial:                  t.dial,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
		}
	}
	return t, nil
}

func (t *piph2) ID() string {
	return t.id
}

func (t *piph2) Type() string {
	return PIPH2
}

func (t *piph2) GetAddr() string {
	return t.hostname + ":" + strconv.Itoa(t.port)
}

func (t *piph2) Stop() error {
	t.status = END
	return nil
}

func (t *piph2) Status() int {
	return t.status
}

func (t *piph2) claim(msg string) string {
	if len(t.token) == 0 || len(t.sig) == 0 {
		return ""
	}
	// hmac msg keyed by token's sig
	msgmac := hmac256(hex2byte(msg), hex2byte(t.sig))
	return t.token + ":" + t.sig + ":" + byte2hex(msgmac)
}

func (t *piph2) Dial(network, addr string) (Conn, error) {
	if t.status == END {
		return nil, errProxyStopped
	}
	if network != "tcp" {
		return nil, errUnexpectedProxy
	}

	u, err := url.Parse(t.url)
	if err != nil {
		return nil, err
	}
	ipp, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.Path += ipp.Addr().String() + "/" + strconv.Itoa(int(ipp.Port())) + "/" + network

	// ref: github.com/ginuerzh/gost/blob/1c62376e0880e/http2.go#L221
	// and: github.com/golang/go/issues/17227#issuecomment-249424243
	readable, writable := io.Pipe()
	// multipart? stackoverflow.com/questions/39761910
	// mpw := multipart.NewWriter(writable)
	incomingch := make(chan io.ReadCloser, 1)
	oconn := &pipconn{
		id:    u.Path,
		rch:   incomingch,
		w:     writable,
		raddr: net.TCPAddrFromAddrPort(ipp),
		wmu:   new(sync.Mutex),
		rmu:   new(sync.Mutex),
	}

	// github.com/golang/go/issues/26574
	req, err := http.NewRequest(http.MethodPut, u.String(), io.NopCloser(readable))

	if err != nil {
		log.E("piph2: req err: %v", err)
		t.status = TKO
		closePipe(readable, writable)
		return nil, err
	}
	msg, err := hexnonce(ipp)
	if err != nil {
		log.E("piph2: nonce err: %v", err)
		closePipe(readable, writable)
		return nil, err
	}

	trace := httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			log.V("piph2: %s GetConn(%s)", u.Path, hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			log.D("piph2: GotConn([%v -> %v] (via %v))", info.Conn.LocalAddr(), ipp.Addr().String(), info.Conn.RemoteAddr())
			oconn.laddr = info.Conn.LocalAddr()
		},
		PutIdleConn: func(err error) {
			log.V("piph2: %s PutIdleConn(%v)", u.Path, err)
		},
		GotFirstResponseByte: func() {
			log.V("piph2: %s GotFirstResponseByte()", u.Path)
		},
		Got100Continue: func() {
			log.V("piph2: %s Got100Continue()", u.Path)
		},
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			log.V("piph2: %s Got1xxResponse(%d, %v)", u.Path, code, header)
			return nil
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			log.V("piph2: %s DNSStart(%v)", u.Path, info)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			log.V("piph2: %s DNSDone(%v)", u.Path, info)
		},
		ConnectStart: func(network, addr string) {
			log.V("piph2: %s ConnectStart(%s, %s)", u.Path, network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			log.V("piph2: %s ConnectDone(%s, %s, %v)", u.Path, network, addr, err)
		},
		TLSHandshakeStart: func() {
			log.V("piph2: %s TLSHandshakeStart()", u.Path)
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			log.V("piph2: %s TLSHandshakeDone(%v, %v)", u.Path, state, err)
		},
		WroteHeaders: func() {
			log.V("piph2: %s WroteHeaders()", u.Path)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			log.V("piph2: %s WroteRequest(%v)", u.Path, info)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))

	log.D("piph2: req %s", u.String())
	req.ContentLength = -1 // infinite length?
	req.Close = false      // allow keep-alive
	// github.com/stripe/stripe-go/pull/711
	req.GetBody = func() (io.ReadCloser, error) {
		log.V("piph2: %s GetBody()", u.Path)
		return io.NopCloser(readable), nil
	}
	req.Header.Set("User-Agent", "")
	// sse? community.cloudflare.com/t/184219
	// pack binary data into utf-8?
	// stackoverflow.com/a/31661586
	// go.dev/play/p/NPsulbF2y9X
	// req.Header.Set("Content-Type", "text/event-stream")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("x-nile-pip-claim", t.claim(msg))
	req.Header.Set("x-nile-pip-msg", msg)

	go func() {
		res, err := t.client.Do(req)
		if err != nil {
			log.E("piph2: path(%s) send err: %v", u.Path, err)
			t.status = TKO
			incomingch <- nil
			closePipe(readable, writable)
		} else if res.StatusCode != http.StatusOK {
			log.E("piph2: path(%s) recv bad: %v", u.Path, res.Status)
			res.Body.Close()
			t.status = TKO
			incomingch <- nil
			closePipe(readable, writable)
		} else {
			log.D("piph2: duplex %s", u.String())
			// github.com/posener/h2conn/blob/13e7df33ed1/client.go
			res.Request = req
			t.status = TOK
			incomingch <- res.Body
		}
	}()

	t.status = TOK
	return oconn, nil
}

func closePipe(c ...io.Closer) {
	for _, x := range c {
		x.Close()
	}
}

func hmac256(m, k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	return mac.Sum(nil)
}

func hexnonce(ipport netip.AddrPort) (n string, err error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err == nil {
		nonce = append(nonce, ipport.Addr().AsSlice()...)
		n = byte2hex(nonce)
	} else {
		log.E("piph2: hexnonce: err %v", err)
	}
	return
}

func hex2byte(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.E("piph2: hex2byte: err %v", err)
	}
	return b
}

func byte2hex(b []byte) string {
	return hex.EncodeToString(b)
}

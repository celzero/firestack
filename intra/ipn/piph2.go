// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"golang.org/x/net/http2"
)

type piph2 struct {
	nofwd                        // no forwarding/listening
	protoagnostic                // since dial, dialts are proto aware
	skiprefresh                  // no refresh
	id            string         // some unique identifier
	url           string         // h2 proxy url
	hostname      string         // h2 proxy hostname
	port          int            // h2 proxy port
	token         string         // hex, client token
	toksig        string         // hex, authorizer signed client token
	rsasig        string         // hex, authorizer unblinded signature
	client        http.Client    // h2 client, see trType
	proxydialer   *protect.RDial // h2 dialer
	hc            *http.Client   // exported http client
	rd            *protect.RDial // exported dialer
	lastdial      time.Time      // last dial time
	status        int            // proxy status: TOK, TKO, END
	opts          *settings.ProxyOptions
}

// github.com/posener/h2conn/blob/13e7df33ed1/conn.go
type pipconn struct {
	core.TCPConn
	id    string               // some identifier
	rch   <-chan io.ReadCloser // reader provider
	wch   chan<- int64         // first write len(data)
	ok    bool                 // r is ok to read from
	r     io.ReadCloser        // reader, nil until ok is true
	w     io.WriteCloser       // writer
	laddr net.Addr             // local address, may be nil
	raddr net.Addr             // remote address
}

func (c *pipconn) Read(b []byte) (int, error) {
	log.V("piph2: read(%v/%s) waiting?(%t)", len(b), c.id, !c.ok)
	if !c.ok {
		c.r = <-c.rch // nil on error
		c.ok = true
	}
	if core.IsNil(c.r) {
		log.E("piph2: read(%v/%s) not ok", len(b), c.id)
		return 0, io.EOF
	}
	return c.r.Read(b)
}

func (c *pipconn) Write(b []byte) (int, error) {
	c.wch <- int64(len(b))
	log.V("piph2: write(%v/%s) read-waiting?(%t)", len(b), c.id, !c.ok)
	if c.w == nil {
		log.E("piph2: write(%v/%s) not ok", len(b), c.id)
		return 0, io.EOF
	}
	return c.w.Write(b)
}

func (c *pipconn) Close() (err error) {
	log.D("piph2: close(%s); waiting?(%t)", c.id, c.ok)
	c.CloseRead()
	c.CloseWrite()
	return nil
}

func (c *pipconn) CloseRead() {
	core.Close(c.r)
}

func (c *pipconn) CloseWrite() {
	core.Close(c.w)
}

func (c *pipconn) LocalAddr() net.Addr           { return c.laddr }
func (c *pipconn) RemoteAddr() net.Addr          { return c.raddr }
func (c *pipconn) SetDeadline(t time.Time) error { return nil }
func SetReadDeadline(t time.Time) error          { return nil }
func SetWriteDeadline(t time.Time) error         { return nil }

func (t *piph2) dialtls(network, addr string, cfg *tls.Config) (net.Conn, error) {
	rawConn, err := t.dial(network, addr)
	if err != nil || rawConn == nil || core.IsNil(rawConn) {
		return nil, errors.Join(err, errNoProxyConn)
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if cfg == nil {
		cfg = &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}
	} else if cfg.ServerName == "" {
		if cfg = cfg.Clone(); cfg != nil {
			cfg.ServerName = hostname
		}
	}

	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(context.Background()); err != nil {
		log.D("piph2: dialtls(%s) handshake error: %v", addr, err)
		core.CloseConn(rawConn)
		return nil, err
	}
	return conn, nil
}

// dial dials proxy addr using the proxydialer via dialers.SplitDial,
// which is aware of proto changes.
func (t *piph2) dial(network, addr string) (net.Conn, error) {
	return dialers.SplitDial(t.proxydialer, network, addr)
}

func NewPipProxy(id string, ctl protect.Controller, po *settings.ProxyOptions) (*piph2, error) {
	if po == nil {
		return nil, errMissingProxyOpt
	}

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

	splitpath := strings.Split(parsedurl.Path, "/")
	if len(splitpath) < 3 {
		return nil, errNoSig
	}
	trType := splitpath[1]
	if trType != "h2" && trType != "h3" {
		return nil, errProxyConfig
	}
	rsasig := splitpath[2]
	// todo: check if the len(rsasig) is 64/128 hex chars?
	if len(rsasig) == 0 {
		return nil, errNoSig
	}
	dialer := protect.MakeNsRDial(id, ctl)
	t := &piph2{
		id:          id,
		url:         parsedurl.String(),
		hostname:    parsedurl.Hostname(),
		port:        port,
		proxydialer: dialer,
		token:       po.Auth.User,
		toksig:      po.Auth.Password,
		rsasig:      rsasig,
		status:      TUP,
		opts:        po,
	}
	t.rd = newRDial(t)
	t.hc = newHTTPClient(t.rd)

	_, ok := dialers.New(t.hostname, po.Addrs) // po.Addrs may be nil or empty
	if !ok {
		log.W("piph2: zero bootstrap ips %s", t.hostname)
	}

	if trType == "h3" {
		// 	github.com/quic-go/quic-go v0.36.1
		// t.client.Transport = &http3.RoundTripper{}
		log.W("piph2: h3 not supported yet")
		t.client.Transport = &http2.Transport{
			DialTLS: t.dialtls,
		}
	} else if trType == "h2" {
		// h2 is duplex: github.com/golang/go/issues/19653#issuecomment-341539160
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

func (*piph2) Router() x.Router {
	return PROXYGATEWAY
}

func (t *piph2) Stop() error {
	t.status = END
	return nil
}

func (t *piph2) Status() int {
	if t.status != END && idling(t.lastdial) {
		return TZZ
	}
	return t.status
}

// Scenario 4: privacypass.github.io/protocol
func (t *piph2) claim(msg string) []string {
	if len(t.token) == 0 || len(t.toksig) == 0 {
		return nil
	}
	// hmac msg keyed by token's sig
	msgmac := hmac256(hex2byte(msg), hex2byte(t.toksig))
	return []string{t.token, byte2hex(msgmac)}
}

// Dial implements Proxy.
func (t *piph2) Dial(network, addr string) (protect.Conn, error) {
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
	domain, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.Path += domain + "/" + port + "/" + t.rsasig

	// ref: github.com/ginuerzh/gost/blob/1c62376e0880e/http2.go#L221
	// and: github.com/golang/go/issues/17227#issuecomment-249424243
	readable, writable := io.Pipe()
	// multipart? stackoverflow.com/questions/39761910
	// mpw := multipart.NewWriter(writable)
	// todo: buffered chan may slow down the client
	incomingCh := make(chan io.ReadCloser, 1)
	wlenCh := make(chan int64, 1)
	oconn := &pipconn{
		id:  u.Path,
		rch: incomingCh,
		wch: wlenCh,
		w:   writable, // never nil
	}

	// github.com/golang/go/issues/26574
	req, err := http.NewRequest(http.MethodPut, u.String(), io.NopCloser(readable))

	if err != nil {
		log.E("piph2: req err: %v", err)
		t.status = TKO
		closePipe(readable, writable)
		return nil, err
	}

	msg := fixedMsgHex // 16 bytes; fixed
	if uniqClaimPerUrl {
		msg = hexurl(u.Path) // 32 bytes; per url
	} else {
		u.Path = u.Path + "/" + msg
	}

	trace := httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			log.V("piph2: %s GetConn(%s)", u.Path, hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			oconn.laddr = info.Conn.LocalAddr()
			oconn.raddr = info.Conn.RemoteAddr()
			log.D("piph2: GotConn([%v -> %v] (via %v))", oconn.laddr, addr, oconn.raddr)
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
	// infinite length? doesn't work with cloudflare
	// req.ContentLength = -1
	req.Close = false // allow keep-alive
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
	msgmac := t.claim(msg)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	if msgmac != nil {
		req.Header.Set("x-nile-pip-claim", msgmac[0])
		req.Header.Set("x-nile-pip-mac", msgmac[1])
		// msg is implicitly hex(sha256(url.Path))
		// req.Header.Set("x-nile-pip-msg", msg)
	}

	t.lastdial = time.Now()
	go func() {
		// fixme: currently, this hangs forever when upstream is cloudflare
		// setting the content-length to the first len(first-write-bytes) works
		// with cloudflare, but then golang's h2 client isn't happy about sending
		// more data than what's defined in content-length:
		// github.com/golang/go/issues/32728
		req.ContentLength = <-wlenCh
		res, err := t.client.Do(req)
		if err != nil || res == nil {
			log.E("piph2: path(%s) send err: %v", u.Path, err)
			t.status = TKO
			incomingCh <- nil
			closePipe(readable, writable)
		} else if res.StatusCode != http.StatusOK {
			log.E("piph2: path(%s) recv bad: %v", u.Path, res.Status)
			core.Close(res.Body)
			t.status = TKO
			incomingCh <- nil
			closePipe(readable, writable)
		} else {
			log.D("piph2: duplex %s", u.String())
			// github.com/posener/h2conn/blob/13e7df33ed1/client.go
			res.Request = req
			t.status = TOK
			incomingCh <- res.Body
		}
	}()

	t.status = TOK
	return oconn, nil
}

func (h *piph2) fetch(req *http.Request) (*http.Response, error) {
	stopped := h.status == END
	if stopped {
		return nil, errProxyStopped
	}
	return h.hc.Do(req)
}

func (h *piph2) Dialer() *protect.RDial {
	return h.rd
}

func (h *piph2) DNS() string {
	return nodns
}

func closePipe(ps ...io.Closer) {
	for _, c := range ps {
		core.CloseOp(c, core.CopAny)
	}
}

func hmac256(m, k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	return mac.Sum(nil)
}

func hexurl(p string) string {
	digest := sha256.Sum256([]byte(p))
	return hex.EncodeToString(digest[:])
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

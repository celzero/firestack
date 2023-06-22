// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core/ipmap"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/split"
)

const (
	tlsHandshakeTimeout   time.Duration = 3 * time.Second
	responseHeaderTimeout time.Duration = 3 * time.Second
)

type piph2 struct {
	Proxy
	id       string
	url      string
	hostname string
	port     int
	ips      ipmap.IPMap
	token    string // hex, client token
	sig      string // hex, authorizer signed client token
	client   http.Client
	dialer   *net.Dialer
	status   int
}

type pipconn struct {
	Conn
	rch <-chan io.ReadCloser
	ok  bool
	r   io.ReadCloser
	w   io.WriteCloser
}

func (c *pipconn) Read(b []byte) (int, error) {
	if !c.ok {
		c.r = <-c.rch // nil on error
		c.ok = true
	}
	if c.r == nil {
		return 0, io.EOF
	}
	return c.r.Read(b)
}

func (c *pipconn) Write(b []byte) (int, error) {
	if c.w == nil {
		return 0, io.EOF
	}
	return c.w.Write(b)
}

func (c *pipconn) Close() (err error) {
	if c.r != nil {
		c.r.Close()
	}
	if c.w != nil {
		err = c.w.Close()
	}
	return
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

	// TODO: Improve IP fallback strategy with parallelism and Happy Eyeballs.
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
	t.client.Transport = &http.Transport{
		Dial:                  t.dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
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
	url, err := url.Parse(t.url)
	if err != nil {
		return nil, err
	}
	ipp, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(url.Path, "/") {
		url.Path += "/"
	}
	url.Path += ipp.Addr().String() + "/" + strconv.Itoa(int(ipp.Port())) + "/" + network

	// ref: github.com/ginuerzh/gost/blob/1c62376e0880e/http2.go#L221
	// and: github.com/golang/go/issues/17227#issuecomment-249424243
	readable, writable := io.Pipe()
	// github.com/golang/go/issues/26574
	req, err := http.NewRequest(http.MethodPut, url.String(), ioutil.NopCloser(readable))
	if err != nil {
		log.E("piph2: req err: %v", err)
		t.status = TKO
		closeAll(readable, writable)
		return nil, err
	}
	msg, err := hexnonce(ipp)
	if err != nil {
		log.E("piph2: nonce err: %v", err)
		closeAll(readable, writable)
		return nil, err
	}

	trace := httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			log.V("piph2: GetConn(%s)", hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			log.D("piph2: GotConn(%v)", info)
			if info.Conn == nil {
				return
			}
			// conn = info.Conn
		},
		PutIdleConn: func(err error) {
			log.V("piph2: PutIdleConn(%v)", err)
		},
		GotFirstResponseByte: func() {
			log.V("piph2: GotFirstResponseByte()")
		},
		Got100Continue: func() {
			log.V("piph2: %s Got100Continue()")
		},
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			log.V("piph2: Got1xxResponse(%d, %v)", code, header)
			return nil
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			log.V("piph2: DNSStart(%v)", info)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			log.V("piph2: DNSDone(%v)", info)
		},
		ConnectStart: func(network, addr string) {
			log.V("piph2: ConnectStart(%s, %s)", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			log.V("piph2: ConnectDone(%s, %s, %v)", network, addr, err)
		},
		TLSHandshakeStart: func() {
			log.V("piph2: TLSHandshakeStart()")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			log.V("piph2: TLSHandshakeDone(%v, %v)", state, err)
		},
		WroteHeaders: func() {
			log.V("piph2: WroteHeaders()")
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			log.V("piph2: WroteRequest(%v)", info)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &trace))

	log.D("piph2: req %s", url.String())
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

	incomingch := make(chan io.ReadCloser, 1)
	go func() {
		res, err := t.client.Do(req)
		incomingch <- res.Body
		if err != nil {
			log.E("piph2: send err: %v", err)
			t.status = TKO
			incomingch <- nil
			closeAll(readable, writable)
			// return nil, err
		} else if res.StatusCode != http.StatusOK {
			log.E("piph2: recv bad status: %v", res.Status)
			res.Body.Close()
			t.status = TKO
			incomingch <- nil
			closeAll(readable, writable)
			// return nil, errNoProxyResponse
		}
		log.D("piph2: duplex %s", url.String())
	}()

	t.status = TOK
	return &pipconn{
		rch: incomingch,
		w:   writable,
	}, nil
}

func closeAll(c ...io.Closer) {
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

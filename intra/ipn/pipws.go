// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
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
	"nhooyr.io/websocket"
)

const (
	writeTimeout    time.Duration = 10 * time.Second
	uniqClaimPerUrl               = false                              // generate a new claim per url
	fixedMsgHex                   = "aecdcde241e3196f2252738c11467baf" // some fixed hex; 16 bytes
)

type pipws struct {
	nofwd                             // no forwarding/listening
	protoagnostic                     // since dial is proto aware
	skiprefresh                       // no refresh
	gw                                // dual stack gateway
	url           string              // ws proxy url
	hostname      string              // ws proxy hostname
	port          int                 // ws proxy port
	token         string              // hex, raw client token
	toksig        string              // hex, authorizer (rdns) signed client token
	rsasighash    string              // hex, authorizer sha256(unblinded signature)
	echcfg        *tls.Config         // ech config
	client        http.Client         // ws client
	client3       *http.Client        // ws client for ech
	outbound      *protect.RDial      // ws dialer
	lastdial      time.Time           // last dial time
	status        *core.Volatile[int] // proxy status: TOK, TKO, END
	opts          *settings.ProxyOptions
}

var _ core.TCPConn = (*pipwsconn)(nil)

// pipwsconn minimally adapts net.Conn to the core.TCPConn interface
type pipwsconn struct {
	net.Conn
}

func (c *pipwsconn) CloseRead() error  { return c.Close() }
func (c *pipwsconn) CloseWrite() error { return c.Close() }

// connects to the ws proxy at addr over tcp; used by t.client
// dial is aware of proto changes via dialers.SplitDial
func (t *pipws) dial(network, addr string) (net.Conn, error) {
	if settings.Loopingback.Load() { // no split in loopback (rinr) mode
		return dialers.Dial(t.outbound, network, addr)
	} else {
		return dialers.SplitDial(t.outbound, network, addr)
	}
}

func (t *pipws) wsconn(rurl, msg string) (c net.Conn, res *http.Response, err error) {
	var ws *websocket.Conn
	ctx := context.TODO()
	msgmac := t.claim(msg) // msg is hex(sha256(url.Path)) or fixedMsgHex
	hdrs := http.Header{}
	hdrs.Set("User-Agent", "")
	if msgmac != nil {
		hdrs.Set("x-nile-pip-msg", msg)
		hdrs.Set("x-nile-pip-claim", msgmac[0]) // client token (po.User)
		hdrs.Set("x-nile-pip-mac", msgmac[1])   // hmac derived from token-sig (po.Password)
		// msg is implicitly hex(sha256(url.Path))
		// hdrs.Set("x-nile-pip-msg", msg)
	}

	log.D("pipws: connecting to %s", rurl)

	if c3 := t.client3; c3 != nil { // ech with tls v3
		ws, res, err = websocket.Dial(ctx, rurl, &websocket.DialOptions{
			HTTPClient: c3,
			HTTPHeader: hdrs,
		})

		if eerr := new(tls.ECHRejectionError); errors.As(err, &eerr) {
			closeWs(ws, "ech rejected")
			ech := eerr.RetryConfigList
			log.I("pipws: ech rejected; new? %d, err: %v", len(ech), eerr)
			if len(ech) > 0 { // retry with new ech
				t.echcfg.EncryptedClientHelloConfigList = ech
				// TODO: is this necessary given echcfg is already set?
				t.client3.Transport = t.h2(t.echcfg)
				// retry with new ech
				ws, res, err = websocket.Dial(ctx, rurl, &websocket.DialOptions{
					HTTPClient: t.client3,
					HTTPHeader: hdrs,
				})
			}
		}
	}
	// err nil when there's no ech; err non-nil when ech fails
	if err != nil || ws == nil || res == nil { // fallback or use tls v2
		closeWs(ws, "fallback")

		log.D("pipws: fallback to tls v2; err? %v", rurl, err) // err maybe nil
		ws, res, err = websocket.Dial(ctx, rurl, &websocket.DialOptions{
			// compression does not work with Workers
			// CompressionMode: websocket.CompressionNoContextTakeover,
			HTTPClient: &t.client,
			HTTPHeader: hdrs,
		})
	}
	if err != nil || ws == nil || res == nil {
		closeWs(ws, "dial err")
		if err == nil {
			err = errNoProxyConn
		}
		log.E("pipws: dialing %s (ws? %t, hres? %t); err: %v\n",
			rurl, ws == nil, res == nil, err)
		return
	}

	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	c = &pipwsconn{conn}
	return
}

// NewPipWsProxy creates a new pipws proxy with the given id, controller, and proxy options.
// The proxy options must contain a valid URL, and the URL must have a path with the format "/ws/<sha256(rsasig)>".
// The proxy options must also contain a valid auth user (raw client token) and
// password (expiry + signed raw client token).
func NewPipWsProxy(ctl protect.Controller, po *settings.ProxyOptions) (*pipws, error) {
	if po == nil {
		return nil, errMissingProxyOpt
	}

	parsedurl, err := url.Parse(po.Url())
	if err != nil {
		return nil, err
	}
	// may be "pipws"
	if parsedurl.Scheme != "wss" {
		parsedurl.Scheme = "wss"
	}
	portStr := parsedurl.Port()
	var port int
	if len(portStr) <= 0 {
		portStr = "443"
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	splitpath := strings.Split(parsedurl.Path, "/")
	// todo: check if the len(rsasig) is 64/128 hex chars?
	if len(splitpath) < 3 {
		return nil, errNoSig
	}
	if (splitpath[1] != "ws" && splitpath[1] != "wss") || len(splitpath[3]) <= 0 {
		return nil, errProxyConfig
	}
	dialer := protect.MakeNsRDial(RpnWs, ctl)
	t := &pipws{
		url:        parsedurl.String(),
		hostname:   parsedurl.Hostname(),
		port:       port,
		outbound:   dialer,
		token:      po.Auth.User,
		toksig:     po.Auth.Password,
		rsasighash: splitpath[2],
		status:     core.NewVolatile(TUP),
		opts:       po,
	}

	_, ok := dialers.New(t.hostname, po.Addrs) // po.Addrs may be nil or empty
	if !ok {
		log.W("pipws: zero bootstrap ips %s", t.hostname)
	}

	tlscfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: false,
		ClientSessionCache:     core.TlsSessionCache(),
	}
	ech := t.ech()
	if len(ech) > 0 {
		t.client3 = new(http.Client)
		t.echcfg = &tls.Config{
			MinVersion:                     tls.VersionTLS13, // must be 1.3
			EncryptedClientHelloConfigList: ech,
			SessionTicketsDisabled:         false,
			ClientSessionCache:             core.TlsSessionCache(),
		}
		t.client3.Transport = t.h2(t.echcfg)
	}
	t.client.Transport = t.h2(tlscfg)

	log.I("pipws: host: %s:%s, sig: %s, ech? %t", t.hostname, portStr, t.rsasighash[:6], t.client3 != nil)
	return t, nil
}

func (t *pipws) h2(cfg *tls.Config) *http.Transport {
	return &http.Transport{
		Dial:                  t.dial,
		TLSHandshakeTimeout:   writeTimeout,
		ResponseHeaderTimeout: writeTimeout,
		TLSClientConfig:       cfg,
	}
}

func (t *pipws) ID() string {
	return RpnWs
}

func (t *pipws) Type() string {
	return PIPWS
}

func (t *pipws) GetAddr() string {
	return t.hostname + ":" + strconv.Itoa(t.port)
}

func (t *pipws) Router() x.Router {
	return t
}

// Reaches implements x.Router.
func (t *pipws) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(t, hostportOrIPPortCsv)
}

func (t *pipws) Stop() error {
	t.status.Store(END)
	log.I("pipws: stopped")
	return nil
}

func (t *pipws) Status() int {
	s := t.status.Load()
	if s != END && idling(t.lastdial) {
		return TZZ
	}
	return s
}

// Scenario 4: privacypass.github.io/protocol
func (t *pipws) claim(msg string) []string {
	if len(t.token) == 0 || len(t.toksig) == 0 {
		return nil
	}
	// hmac(msg aka url.path) keyed to hmac-signed(token)
	msgmac := hmac256(hex2byte(msg), hex2byte(t.toksig))
	return []string{t.token, byte2hex(msgmac)}
}

// Dial connects to addr via wsconn over this ws proxy
func (t *pipws) Dial(network, addr string) (protect.Conn, error) {
	if t.status.Load() == END {
		return nil, errProxyStopped
	}
	// tcp, tcp4, tcp6
	if !strings.Contains(network, "tcp") {
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
	u.Path += domain + "/" + port + "/" + t.rsasighash

	msg := fixedMsgHex // 16 bytes; fixed
	if uniqClaimPerUrl {
		msg = hexurl(u.Path) // 32 bytes; per url
	} else {
		u.Path = u.Path + "/" + msg
	}

	rurl := u.String()
	c, res, err := t.wsconn(rurl, msg)
	t.lastdial = time.Now()
	if err != nil {
		core.CloseConn(c)
		log.E("pipws: req %s err: %v", rurl, err)
		t.status.Store(TKO)
		return nil, err
	}
	if res.StatusCode != 101 {
		core.CloseConn(c)
		log.E("pipws: %s res not ws %d", rurl, res.StatusCode)
		t.status.Store(TKO)
		return nil, err
	}

	log.D("pipws: duplex %s", rurl)

	t.status.Store(TOK)
	return c, nil
}

func (h *pipws) Dialer() protect.RDialer {
	return h
}

func (h *pipws) DNS() string {
	return nodns
}

func (h *pipws) ech() []byte {
	name := h.hostname
	if len(name) <= 0 {
		return nil
	} else if v, err := dialers.ECH(name); err != nil {
		log.W("pipws: ech(%s): %v", name, err)
		return nil
	} else {
		log.V("pipws: ech(%s): sz %d", name, len(v))
		return v
	}
}

func closeWs(ws *websocket.Conn, reason string) {
	if ws != nil {
		_ = ws.Close(websocket.StatusNormalClosure, reason)
	}
}

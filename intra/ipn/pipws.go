// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
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
	client        http.Client         // ws client
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
	ctx := context.Background()
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

	log.D("connecting to %s", rurl)

	ws, res, err = websocket.Dial(ctx, rurl, &websocket.DialOptions{
		// compression does not work with Workers
		// CompressionMode: websocket.CompressionNoContextTakeover,
		HTTPClient: &t.client,
		HTTPHeader: hdrs,
	})
	if err != nil {
		log.E("websocket: %v\n", err)
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
	if len(portStr) > 0 {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
	} else {
		port = 443
	}

	splitpath := strings.Split(parsedurl.Path, "/")
	// todo: check if the len(rsasig) is 64/128 hex chars?
	if len(splitpath) < 3 {
		return nil, errNoSig
	}
	if splitpath[1] != "ws" {
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

	t.client.Transport = &http.Transport{
		Dial:                  t.dial,
		TLSHandshakeTimeout:   writeTimeout,
		ResponseHeaderTimeout: writeTimeout,
	}
	return t, nil
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
		log.E("pipws: req err: %v", err)
		t.status.Store(TKO)
		return nil, err
	}
	if res.StatusCode != 101 {
		log.E("pipws: res not ws %d", res.StatusCode)
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

package settings

import (
	"strings"
	"golang.org/x/net/proxy"
)

// TODO: These modes could be covered by bit-flags instead.

// DNSModeNone does no redirects of DNS queries sent to the tunnel.
const DNSModeNone = 0

// DNSModeIP redirects DNS requests sent to the IP endpoint set by VPN.
const DNSModeIP int = 1

// DNSModePort redirects all DNS requests on port 53.
const DNSModePort int = 2

// DNSModeCryptIP redirects DNS requests sent to the IP endpoint set by VPN to DNSCrypt
const DNSModeCryptIP int = 3

// DNSModeCryptPort redirects all DNS requests on port 53 to DNSCrypt.
const DNSModeCryptPort int = 4

// DNSModeProxyIP redirects DNS requests sent to the IP endpoint set by VPN to a DNS Proxy.
const DNSModeProxyIP int = 5

// DNSModeProxyPort redirects all DNS requests on port 53 to a DNS proxy.
const DNSModeProxyPort int = 6

// BlockModeNone filters no packet.
const BlockModeNone int = 0

// BlockModeFilter filters packets on connection establishment.
const BlockModeFilter int = 1

// BlockModeSink blackholes all packets.
const BlockModeSink int = 2

// BlockModeFilterProc determines owner-uid of a tcp/udp connection
// from procfs before filtering
const BlockModeFilterProc int = 3

// ProxyModeNone forwards no packet.
const ProxyModeNone int = 0

// ProxyModeSOCKS5 forwards packets to a SOCKS5 endpoint.
const ProxyModeSOCKS5 int = 1

// ProxyModeHTTPS forwards packets to a HTTPS proxy.
const ProxyModeHTTPS int = 2

// TunMode specifies blocking and dns modes
type TunMode struct {
	// DNSMode specifies the kind of DNS traffic to be trapped and routed to DoH servers
	DNSMode int
	// BlockMode instructs change in firewall behaviour.
	BlockMode int
	// ProxyMode determines where the traffic is forwarded to.
	ProxyMode int
}

// DNSOptions define https or socks5 proxy options
type DNSOptions struct {
	IPPort			string
}

// ProxyOptions define https or socks5 proxy options
type ProxyOptions struct {
	Auth			*proxy.Auth
	IPPort			string
}

// SetMode re-assigns d to DNSMode, b to BlockMode, and p to ProxyMode
func (t *TunMode) SetMode(d int, b int, p int) {
	t.DNSMode = d
	t.BlockMode = b
	t.ProxyMode = p
}

// NewTunMode returns a new TunMode object.
// `d` sets dns-mode.
// `b` sets block-mode.
// `p` sets proxy-mode.
func NewTunMode(d int, b int, p int) *TunMode {
	return &TunMode{
		DNSMode:   d,
		BlockMode: b,
		ProxyMode: p,
	}
}

// DefaultTunMode returns a default TunMode object with
// IP-only DNS capture and replay (not all DNS traffic but
// only the DNS traffic sent to [tcp/udp]handler.fakedns
// is captured and replayed to the remote DoH server)
// and with firewall disabled.
func DefaultTunMode() *TunMode {
	return &TunMode{
		DNSMode:   	DNSModeIP,
		BlockMode: 	BlockModeNone,
		ProxyMode: 	ProxyModeNone,
	}
}

// NewDNSOptions returns a new DNSOpitons object.
func NewDNSOptions(ip string, port string) *DNSOptions {
	// TODO: validate IP and port, protocol
	return &DNSOptions{
		IPPort: 	ip + ":" + port,
	}
}

// NewAuthProxyOptions returns a new ProxyOptions object with authentication object.
func NewAuthProxyOptions(username string, password string, ip string, port string) *ProxyOptions {
	if (len(username) <= 0 || len(password) <= 0) {
		return NewProxyOptions(ip, port)
	}
	auth := proxy.Auth{
		User:     username,
		Password: password,
	}
	// TODO: validate IP and port, protocol
	return &ProxyOptions{
		Auth:   	&auth,
		IPPort: 	ip + ":" + port,
	}
}

// NewProxyOptions returns a new ProxyOptions object.
func NewProxyOptions(ip string, port string) *ProxyOptions {
	// TODO: validate IP and port, protocol
	return &ProxyOptions{
		Auth:   	nil,
		IPPort: 	ip + ":" + port,
	}
}

func (d *DNSOptions) String() string {
	ipport := strings.Split(d.IPPort, ":")
	return ipport[0] + "," + ipport[1]
}

func (p *ProxyOptions) String() string {
	ipport := strings.Split(p.IPPort, ":")
	var username string
	var password string
	if (p.Auth == nil) {
		username = ""
		password = ""
	} else {
		username = p.Auth.User
		password = p.Auth.Password
	}
	return username + "," + password + "," + ipport[0] + "," + ipport[1]
}

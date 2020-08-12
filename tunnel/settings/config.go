package settings

// DNSModeNone does no redirects of DNS queries sent to the tunnel.
const DNSModeNone = 0

// DNSModeIP redirects DNS requests sent to the IP endpoint set by VPN.
const DNSModeIP int = 1

// DNSModePort Redirect all DNS requests on port 53.
const DNSModePort int = 2

// BlockModeNone filters no packet.
const BlockModeNone int = 0

// BlockModeFilter filters packets on connection establishment.
const BlockModeFilter int = 1

// BlockModeSink blackholes all packets.
const BlockModeSink int = 2

// BlockModeFilterProc determines owner-uid of a tcp/udp connection
// from procfs before filtering
const BlockModeFilterProc int = 3

// TunMode specifies blocking and dns modes
type TunMode struct {
	// DNSMode specifies the kind of DNS traffic to be trapped and routed to DoH servers
	DNSMode int
	// BlockMode specifies the kind of DNS traffic to be trapped and routed to DoH servers
	BlockMode int
}

// SetMode re-assigns d to DNSMode and b to BlockMode
func (t *TunMode) SetMode(d int, b int) {
	t.DNSMode = d
	t.BlockMode = b
}

// NewTunMode returns a new TunMode object.
// `d` is the DoH template in string form.
// `b` is the DoH template in string form.
func NewTunMode(d int, b int) *TunMode {
	return &TunMode{
		DNSMode:   d,
		BlockMode: b,
	}
}

// DefaultTunMode returns a default TunMode object with
// IP-only DNS capture and replay (not all DNS traffic but
// only the DNS traffic sent to [tcp/udp]handler.fakedns
// is captured and replayed to the remote DoH server)
// and with firewall disabled.
func DefaultTunMode() *TunMode {
	return &TunMode{
		DNSMode:   DNSModeIP,
		BlockMode: BlockModeNone,
	}
}

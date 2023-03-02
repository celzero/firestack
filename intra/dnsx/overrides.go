package dnsx

import (
	"net"
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

// udp

func (h *resolver) isUdpDnsIpPort(addr *net.UDPAddr) bool {
	if addr == nil || len(h.udpaddrs) <= 0 {
		log.E("nil dst-addr(%v) or dns(%v)", addr, h.udpaddrs)
		return false
	}
	for _, dnsaddr := range h.udpaddrs {
		if addr.IP.Equal(dnsaddr.IP) && addr.Port == dnsaddr.Port {
			return true
		}
	}
	return false
}

func (h *resolver) isUdpDnsPort(addr *net.UDPAddr) bool {
	if addr == nil || len(h.udpaddrs) <= 0 {
		log.E("nil dst-addr(%v) or dns(%v)", addr, h.udpaddrs)
		return false
	}
	// isn't h.fakedns.Port always expected to be 53?
	for _, dnsaddr := range h.udpaddrs {
		if addr.Port == dnsaddr.Port {
			return true
		}
	}
	return false
}

func (h *resolver) isUdpDns(addr *net.UDPAddr) bool {
	if h.trapIP() {
		if yes := h.isUdpDnsIpPort(addr); yes {
			return true
		}
	} else if h.trapPort() {
		if yes := h.isUdpDnsPort(addr); yes {
			return true
		}
	}
	return false
}

// tcp

func (h *resolver) isTcpDnsIpPort(addr *net.TCPAddr) bool {
	if addr == nil || len(h.tcpaddrs) <= 0 {
		log.E("nil dst-addr(%v) or dns(%v)", addr, h.tcpaddrs)
		return false
	}
	for _, dnsaddr := range h.tcpaddrs {
		if addr.IP.Equal(dnsaddr.IP) && addr.Port == dnsaddr.Port {
			return true
		}
	}
	return false
}

func (h *resolver) isTcpDnsPort(addr *net.TCPAddr) bool {
	if addr == nil || len(h.tcpaddrs) <= 0 {
		log.E("nil dst-addr(%v) or dns(%v)", addr, h.tcpaddrs)
		return false
	}
	// isn't h.fakedns.Port always expected to be 53?
	for _, dnsaddr := range h.tcpaddrs {
		if addr.Port == dnsaddr.Port {
			return true
		}
	}
	return false
}

func (h *resolver) isTcpDns(addr *net.TCPAddr) bool {
	if h.trapIP() {
		if yes := h.isTcpDnsIpPort(addr); yes {
			return true
		}
	} else if h.trapPort() {
		if yes := h.isTcpDnsPort(addr); yes {
			return true
		}
	}
	return false
}

// dns

func (h *resolver) isDns(network, ipport string) bool {
	if ipp, err := netip.ParseAddrPort(ipport); err != nil {
		return false
	} else {
		switch network {
		case NetTypeTCP:
			addr := &net.TCPAddr{IP: ipp.Addr().AsSlice(), Port: int(ipp.Port())}
			return h.isTcpDns(addr)
		case NetTypeUDP:
			addr := &net.UDPAddr{IP: ipp.Addr().AsSlice(), Port: int(ipp.Port())}
			return h.isUdpDns(addr)
		default:
			return false
		}
	}
}

func (h *resolver) trapIP() bool {
	return h.tunmode.DNSMode == settings.DNSModeIP
}

func (h *resolver) trapPort() bool {
	return h.tunmode.DNSMode == settings.DNSModePort
}

// TODO: Generics?
func (r *resolver) fakeTcpAddr(csvaddr string) {
	addrs := strings.Split(csvaddr, ",")
	tcpaddrs := make([]*net.TCPAddr, 0, len(addrs))
	count := 0
	for _, a := range addrs {
		if tcpaddr, err := net.ResolveTCPAddr("tcp", a); err != nil {
			log.W("not valid fake tcpaddr(%s): %v", a, err)
		} else if tcpaddr != nil {
			tcpaddrs = append(tcpaddrs, tcpaddr)
			count += 1
		}
	}
	r.tcpaddrs = tcpaddrs[:count]
}

func (r *resolver) fakeUdpAddr(csvaddr string) {
	addrs := strings.Split(csvaddr, ",")
	udpaddrs := make([]*net.UDPAddr, 0, len(addrs))
	count := 0
	for _, a := range addrs {
		if udpaddr, err := net.ResolveUDPAddr("udp", a); err != nil {
			log.W("not valid fake udpaddr(%s): %v", a, err)
		} else if udpaddr != nil {
			udpaddrs = append(udpaddrs, udpaddr)
			count += 1
		}
	}
	r.udpaddrs = udpaddrs[:count]
}

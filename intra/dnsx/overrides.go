package dnsx

import (
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

func (h *resolver) isDnsIpPort(addr netip.AddrPort) bool {
	for _, dnsaddr := range h.dnsaddrs {
		if addr.Compare(dnsaddr) == 0 {
			return true
		}
	}
	return false
}

func (h *resolver) isDnsPort(addr netip.AddrPort) bool {
	// isn't h.fakedns.Port always expected to be 53?
	for _, dnsaddr := range h.dnsaddrs {
		if addr.Port() == dnsaddr.Port() {
			return true
		}
	}
	return false
}

func (h *resolver) isDns(ipp netip.AddrPort) bool {
	if !ipp.IsValid() || len(h.dnsaddrs) <= 0 {
		log.E("dnsx: missing dst-addr(%v) or dns(%v)", ipp, h.dnsaddrs)
		return false
	}
	dnsmode := h.tunmode.DNSMode.Load()
	if dnsmode == settings.DNSModeIP {
		if yes := h.isDnsIpPort(ipp); yes {
			return true
		}
	} else if dnsmode == settings.DNSModePort {
		if yes := h.isDnsPort(ipp); yes {
			return true
		}
	}
	return false
}

func (r *resolver) addDnsAddrs(csvaddr string) {
	addrs := strings.Split(csvaddr, ",")
	dnsaddrs := make([]netip.AddrPort, 0)
	if len(addrs) <= 0 {
		log.E("dnsx: missing dnsaddrs(%s)", csvaddr)
		return
	}
	for _, a := range addrs {
		if ipp, err := netip.ParseAddrPort(a); ipp.IsValid() && err == nil {
			dnsaddrs = append(dnsaddrs, ipp)
		} else {
			log.W("dnsx: not valid fake udpaddr(%s <=> %s): %v", ipp, a, err)
		}
	}
	if len(dnsaddrs) <= 0 {
		log.E("dnsx: no valid dnsaddrs(%s)", csvaddr)
	}
	r.dnsaddrs = dnsaddrs
}

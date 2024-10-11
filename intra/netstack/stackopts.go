// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func SetNetstackOpts(s *stack.Stack) {
	// TODO: other stack otps?
	// github.com/xjasonlyu/tun2socks/blob/31468620e/core/option/option.go#L69

	// TODO: setup protocol opts?
	// github.com/google/gvisor/blob/ef9e8d91/test/benchmarks/tcp/tcp_proxy.go#L233
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	// from: github.com/telepresenceio/telepresence/blob/ab7dda7d55/pkg/vif/stack.go#L232
	// Enable Receive Buffer Auto-Tuning, see: github.com/google/gvisor/issues/1666
	bufauto := tcpip.TCPModerateReceiveBufferOption(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &bufauto)

	// coder.com/blog/delivering-5x-faster-throughput-in-coder-2-12-0
	ccopt := tcpip.CongestionControlOption("cubic")
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccopt)

	ttl := tcpip.DefaultTTLOption(128)
	s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttl)
	s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &ttl)

	if settings.ExperimentalWireGuard.Load() {
		// github.com/tailscale/tailscale/blob/c4d0237e5c/wgengine/netstack/netstack_tcpbuf_default.go
		tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
			Min:     tcp.MinBufferSize,
			Default: tcp.DefaultSendBufferSize,
			Max:     8 << 20, // 8MiB
		}
		tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
			Min:     tcp.MinBufferSize,
			Default: tcp.DefaultReceiveBufferSize,
			Max:     6 << 20, // 6MiB
		}
		// github.com/tailscale/tailscale/blob/c4d0237e5c/wgengine/netstack/netstack.go#L329
		_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt)
		_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt)
	}
}

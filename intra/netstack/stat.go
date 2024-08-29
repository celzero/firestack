// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"errors"
	"strings"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	errNoStack = errors.New("netstat: no stack")
	errNoStat  = errors.New("netstat: no stat")
)

var ba = core.NewKeyedBarrier[*x.NetStat, uint32](10 * time.Second)

func Stat(s *stack.Stack) (out *x.NetStat, err error) {
	if s == nil {
		return nil, errNoStack
	}
	v, _ := ba.Do(s.Seed(), func() (*x.NetStat, error) {
		return stat(s), nil
	})
	if v != nil {
		return v.Val, nil
	}
	return nil, errNoStat
}

func stat(s *stack.Stack) (out *x.NetStat) {
	out = new(x.NetStat)

	stat := s.Stats()
	allinfo := s.NICInfo()
	tcp := stat.TCP
	udp := stat.UDP
	icmp := stat.ICMP
	ip := stat.IP
	nic := stat.NICs

	// nicinfo
	if len(allinfo) > 0 {
		if info, ok := allinfo[settings.NICID]; ok {
			out.NICIn.Name = info.Name
			out.NICIn.Mtu = int32(info.MTU)
			out.NICIn.HwAddr = info.LinkAddress.String()
			addrs := make([]string, 0, len(info.ProtocolAddresses))
			for _, addr := range info.ProtocolAddresses {
				addrs = append(addrs, addr.AddressWithPrefix.String())
			}
			out.NICIn.Addrs = strings.Join(addrs, ",")
			out.NICIn.Arp = int32(info.ARPHardwareType)
			out.NICIn.Up = info.Flags.Up
			out.NICIn.Running = info.Flags.Running
			out.NICIn.Lo = info.Flags.Loopback
			out.NICIn.Promisc = info.Flags.Promiscuous
			out.NICIn.Forwarding4 = info.Forwarding[ipv4.ProtocolNumber]
			out.NICIn.Forwarding6 = info.Forwarding[ipv6.ProtocolNumber]
		} else {
			out.NICIn.Name = "missing"
		}
	} else {
		out.NICIn.Name = "unknown"
	}

	// nic
	out.NICSt.RxBytes = int64(nic.Rx.Bytes.Value())
	out.NICSt.RxPkts = int64(nic.Rx.Packets.Value())
	out.NICSt.TxBytes = int64(nic.Tx.Bytes.Value())
	out.NICSt.TxPkts = int64(nic.Tx.Packets.Value())
	out.NICSt.Drops = int64(nic.TxPacketsDroppedNoBufferSpace.Value())
	out.NICSt.Invalid = int64(nic.MalformedL4RcvdPackets.Value())
	out.NICSt.L3Unknown = int64(summation(nic.UnknownL3ProtocolRcvdPacketCounts))
	out.NICSt.L4Unknown = int64(summation(nic.UnknownL4ProtocolRcvdPacketCounts))
	out.NICSt.L4Drops = int64(stat.DroppedPackets.Value())
	// ip
	out.IPSt.InvalidDst = int64(ip.InvalidDestinationAddressesReceived.Value())
	out.IPSt.InvalidSrc = int64(ip.InvalidSourceAddressesReceived.Value())
	out.IPSt.InvalidFrag = int64(ip.MalformedFragmentsReceived.Value())
	out.IPSt.InvalidPkt = int64(ip.MalformedPacketsReceived.Value())
	out.IPSt.Errs = int64(ip.OutgoingPacketErrors.Value())
	out.IPSt.Rcv = int64(ip.PacketsReceived.Value())
	out.IPSt.Snd = int64(ip.PacketsSent.Value())
	out.IPSt.ErrSnd = out.IPSt.Snd - int64(ip.PacketsDelivered.Value())
	out.IPSt.ErrRcv = out.IPSt.Rcv - int64(ip.ValidPacketsReceived.Value())
	// ip forwarding
	router := ip.Forwarding
	out.FWDSt.Errs = int64(router.Errors.Value())
	out.FWDSt.Timeouts = int64(router.ExhaustedTTL.Value())
	out.FWDSt.Unrch = int64(router.HostUnreachable.Value())
	out.FWDSt.PTB = int64(router.PacketTooBig.Value())
	out.FWDSt.Drops = int64(router.InitializingSource.Value() +
		router.ExtensionHeaderProblem.Value() +
		router.LinkLocalDestination.Value() +
		router.LinkLocalSource.Value() +
		router.NoMulticastPendingQueueBufferSpace.Value() +
		router.OutgoingDeviceNoBufferSpace.Value())
	out.FWDSt.NoRoute = int64(router.Unrouteable.Value())
	out.FWDSt.NoHop = int64(router.UnknownOutputEndpoint.Value())
	// icmp
	out.ICMPSt.Snd4 = int64(icmp.V4.PacketsSent.EchoRequest.Value())
	out.ICMPSt.Snd6 = int64(icmp.V6.PacketsSent.EchoRequest.Value())
	out.ICMPSt.Rcv4 = int64(icmp.V4.PacketsReceived.EchoReply.Value())
	out.ICMPSt.Rcv6 = int64(icmp.V6.PacketsReceived.EchoReply.Value())
	out.ICMPSt.UnrchRcv4 = int64(icmp.V4.PacketsReceived.DstUnreachable.Value())
	out.ICMPSt.UnrchRcv6 = int64(icmp.V6.PacketsReceived.DstUnreachable.Value())
	out.ICMPSt.UnrchSnd4 = int64(icmp.V4.PacketsSent.DstUnreachable.Value())
	out.ICMPSt.UnrchSnd6 = int64(icmp.V6.PacketsSent.DstUnreachable.Value())
	out.ICMPSt.Drops4 = int64(icmp.V4.PacketsSent.Dropped.Value())
	out.ICMPSt.Drops6 = int64(icmp.V6.PacketsSent.Dropped.Value())
	out.ICMPSt.Invalid4 = int64(icmp.V4.PacketsReceived.Invalid.Value())
	out.ICMPSt.Invalid6 = int64(icmp.V6.PacketsReceived.Invalid.Value())
	out.ICMPSt.TimeoutSnd4 = int64(icmp.V4.PacketsSent.TimeExceeded.Value())
	out.ICMPSt.TimeoutSnd6 = int64(icmp.V6.PacketsSent.TimeExceeded.Value())
	out.ICMPSt.TimeoutRcv4 = int64(icmp.V4.PacketsReceived.TimeExceeded.Value())
	out.ICMPSt.TimeoutRcv6 = int64(icmp.V6.PacketsReceived.TimeExceeded.Value())
	// udp
	out.UDPSt.ErrChecksum = int64(udp.ChecksumErrors.Value())
	out.UDPSt.ErrRcv = int64(udp.MalformedPacketsReceived.Value())
	out.UDPSt.ErrSnd = int64(udp.PacketsReceived.Value())
	out.UDPSt.Rcv = int64(udp.PacketsReceived.Value())
	out.UDPSt.Snd = int64(udp.PacketsSent.Value())
	out.UDPSt.PortFail = int64(udp.UnknownPortErrors.Value())
	out.UDPSt.Drops = int64(udp.ReceiveBufferErrors.Value())
	// tcp
	out.TCPSt.Active = int64(tcp.ActiveConnectionOpenings.Value())
	out.TCPSt.Passive = int64(tcp.PassiveConnectionOpenings.Value())
	out.TCPSt.ErrChecksum = int64(tcp.ChecksumErrors.Value())
	out.TCPSt.Est = int64(tcp.CurrentEstablished.Value())
	out.TCPSt.Con = int64(tcp.CurrentConnected.Value())
	out.TCPSt.EstClo = int64(tcp.EstablishedClosed.Value())
	out.TCPSt.EstRst = int64(tcp.EstablishedResets.Value())
	out.TCPSt.EstTo = int64(tcp.EstablishedTimedout.Value())
	out.TCPSt.ConFail = int64(tcp.FailedConnectionAttempts.Value())
	out.TCPSt.PortFail = int64(tcp.FailedPortReservations.Value())
	out.TCPSt.ErrRcv = int64(tcp.InvalidSegmentsReceived.Value())
	out.TCPSt.AckDrop = int64(tcp.ListenOverflowAckDrop.Value())
	out.TCPSt.Snd = int64(tcp.SegmentsSent.Value())
	out.TCPSt.Rcv = int64(tcp.ValidSegmentsReceived.Value())
	out.TCPSt.ErrSnd = int64(tcp.SegmentSendErrors.Value())
	out.TCPSt.SynDrop = int64(tcp.ListenOverflowSynDrop.Value())
	out.TCPSt.Retrans = int64(tcp.Retransmits.Value())
	out.TCPSt.Timeouts = int64(tcp.Timeouts.Value())
	out.TCPSt.Drops = int64(tcp.ForwardMaxInFlightDrop.Value())

	return out
}

func summation(m *tcpip.IntegralStatCounterMap) (sum uint64) {
	if m == nil {
		return
	}
	for _, proto := range m.Keys() {
		if v, ok := m.Get(proto); ok {
			sum += v.Value()
		}
	}
	return sum
}

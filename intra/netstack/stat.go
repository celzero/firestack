// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"errors"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"gvisor.dev/gvisor/pkg/tcpip"
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
	tcp := stat.TCP
	udp := stat.UDP
	icmp := stat.ICMP
	ip := stat.IP
	nic := stat.NICs

	// nic
	out.NICStat.RxBytes = int64(nic.Rx.Bytes.Value())
	out.NICStat.RxPkts = int64(nic.Rx.Packets.Value())
	out.NICStat.TxBytes = int64(nic.Tx.Bytes.Value())
	out.NICStat.TxPkts = int64(nic.Tx.Packets.Value())
	out.NICStat.Drops = int64(nic.TxPacketsDroppedNoBufferSpace.Value())
	out.NICStat.Invalid = int64(nic.MalformedL4RcvdPackets.Value())
	out.NICStat.L3Unknown = int64(summation(nic.UnknownL3ProtocolRcvdPacketCounts))
	out.NICStat.L4Unknown = int64(summation(nic.UnknownL4ProtocolRcvdPacketCounts))
	out.NICStat.L4Drops = int64(stat.DroppedPackets.Value())
	// ip
	out.IPStat.InvalidDst = int64(ip.InvalidDestinationAddressesReceived.Value())
	out.IPStat.InvalidSrc = int64(ip.InvalidSourceAddressesReceived.Value())
	out.IPStat.InvalidFrag = int64(ip.MalformedFragmentsReceived.Value())
	out.IPStat.InvalidPkt = int64(ip.MalformedPacketsReceived.Value())
	out.IPStat.Errs = int64(ip.OutgoingPacketErrors.Value())
	out.IPStat.Rcv = int64(ip.PacketsReceived.Value())
	out.IPStat.Snd = int64(ip.PacketsSent.Value())
	out.IPStat.SndErrs = out.IPStat.Snd - int64(ip.PacketsDelivered.Value())
	out.IPStat.RcvErrs = out.IPStat.Rcv - int64(ip.ValidPacketsReceived.Value())
	// ip forwarding
	router := ip.Forwarding
	out.IPFwdStat.Errs = int64(router.Errors.Value())
	out.IPFwdStat.Timeouts = int64(router.ExhaustedTTL.Value())
	out.IPFwdStat.Unrch = int64(router.HostUnreachable.Value())
	out.IPFwdStat.PTB = int64(router.PacketTooBig.Value())
	out.IPFwdStat.Drops = int64(router.InitializingSource.Value() +
		router.ExtensionHeaderProblem.Value() +
		router.LinkLocalDestination.Value() +
		router.LinkLocalSource.Value() +
		router.NoMulticastPendingQueueBufferSpace.Value() +
		router.OutgoingDeviceNoBufferSpace.Value())
	out.IPFwdStat.NoRoute = int64(router.Unrouteable.Value())
	out.IPFwdStat.NoHop = int64(router.UnknownOutputEndpoint.Value())
	// icmp
	out.ICMPStat.Snd4 = int64(icmp.V4.PacketsSent.EchoRequest.Value())
	out.ICMPStat.Snd6 = int64(icmp.V6.PacketsSent.EchoRequest.Value())
	out.ICMPStat.Rcv4 = int64(icmp.V4.PacketsReceived.EchoReply.Value())
	out.ICMPStat.Rcv6 = int64(icmp.V6.PacketsReceived.EchoReply.Value())
	out.ICMPStat.UnrchRcv4 = int64(icmp.V4.PacketsReceived.DstUnreachable.Value())
	out.ICMPStat.UnrchRcv6 = int64(icmp.V6.PacketsReceived.DstUnreachable.Value())
	out.ICMPStat.UnrchSnd4 = int64(icmp.V4.PacketsSent.DstUnreachable.Value())
	out.ICMPStat.UnrchSnd6 = int64(icmp.V6.PacketsSent.DstUnreachable.Value())
	out.ICMPStat.Drops4 = int64(icmp.V4.PacketsSent.Dropped.Value())
	out.ICMPStat.Drops6 = int64(icmp.V6.PacketsSent.Dropped.Value())
	out.ICMPStat.Invalid4 = int64(icmp.V4.PacketsReceived.Invalid.Value())
	out.ICMPStat.Invalid6 = int64(icmp.V6.PacketsReceived.Invalid.Value())
	out.ICMPStat.TimeoutSnd4 = int64(icmp.V4.PacketsSent.TimeExceeded.Value())
	out.ICMPStat.TimeoutSnd6 = int64(icmp.V6.PacketsSent.TimeExceeded.Value())
	out.ICMPStat.TimeoutRcv4 = int64(icmp.V4.PacketsReceived.TimeExceeded.Value())
	out.ICMPStat.TimeoutRcv6 = int64(icmp.V6.PacketsReceived.TimeExceeded.Value())
	// udp
	out.UDPStat.ChecksumErrs = int64(udp.ChecksumErrors.Value())
	out.UDPStat.RcvErrs = int64(udp.MalformedPacketsReceived.Value())
	out.UDPStat.SndErrs = int64(udp.PacketsReceived.Value())
	out.UDPStat.Rcv = int64(udp.PacketsReceived.Value())
	out.UDPStat.Snd = int64(udp.PacketsSent.Value())
	out.UDPStat.PortFail = int64(udp.UnknownPortErrors.Value())
	out.UDPStat.Drops = int64(udp.ReceiveBufferErrors.Value())
	// tcp
	out.TCPStat.Active = int64(tcp.ActiveConnectionOpenings.Value())
	out.TCPStat.Passive = int64(tcp.PassiveConnectionOpenings.Value())
	out.TCPStat.ChecksumErrs = int64(tcp.ChecksumErrors.Value())
	out.TCPStat.Est = int64(tcp.CurrentEstablished.Value())
	out.TCPStat.Con = int64(tcp.CurrentConnected.Value())
	out.TCPStat.EstClo = int64(tcp.EstablishedClosed.Value())
	out.TCPStat.EstRst = int64(tcp.EstablishedResets.Value())
	out.TCPStat.EstTo = int64(tcp.EstablishedTimedout.Value())
	out.TCPStat.ConFail = int64(tcp.FailedConnectionAttempts.Value())
	out.TCPStat.PortFail = int64(tcp.FailedPortReservations.Value())
	out.TCPStat.RcvErrs = int64(tcp.InvalidSegmentsReceived.Value())
	out.TCPStat.AckDrop = int64(tcp.ListenOverflowAckDrop.Value())
	out.TCPStat.Snd = int64(tcp.SegmentsSent.Value())
	out.TCPStat.Rcv = int64(tcp.ValidSegmentsReceived.Value())
	out.TCPStat.SndErrs = int64(tcp.SegmentSendErrors.Value())
	out.TCPStat.SynDrop = int64(tcp.ListenOverflowSynDrop.Value())
	out.TCPStat.Retrans = int64(tcp.Retransmits.Value())
	out.TCPStat.Timeouts = int64(tcp.Timeouts.Value())
	out.TCPStat.Drops = int64(tcp.ForwardMaxInFlightDrop.Value())

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

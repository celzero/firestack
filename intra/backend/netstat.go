// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

type NICStat struct {
	RxBytes   int64 // bytes received
	RxPkts    int64 // packets received
	TxBytes   int64 // bytes sent
	TxPkts    int64 // packets sent
	Invalid   int64 // invalid packets
	L4Unknown int64 // unknown l4 packets
	L3Unknown int64 // unknown l3 packets
	L4Drops   int64 // l4 drops
	Drops     int64 // drops
}

type IPFwdStat struct {
	Errs     int64 // errors
	Unrch    int64 // unreachable
	NoRoute  int64 // no route
	NoHop    int64 // no endpoint
	PTB      int64 // packet too big
	Timeouts int64 // TTL timeouts
	Drops    int64 // drops
}

type IPStat struct {
	InvalidDst  int64 // invalid destination addresses
	InvalidSrc  int64 // invalid source addresses
	InvalidFrag int64 // invalid fragments
	InvalidPkt  int64 // invalid packets
	Errs        int64 // packet errors
	Rcv         int64 // packets received from l2
	Snd         int64 // packets sent to l4
	RcvErrs     int64 // packet receive errors from l2
	SndErrs     int64 // packet send errors to l4
}

type ICMPStat struct {
	Rcv4        int64 // ICMPv4 messages received
	Rcv6        int64 // ICMPv6 messages received
	Snd4        int64 // ICMPv4 messages sent
	Snd6        int64 // ICMPv6 messages sent
	UnrchRcv4   int64 // ICMPv4 unreachable received
	UnrchRcv6   int64 // ICMPv6 unreachable received
	UnrchSnd4   int64 // ICMPv4 unreachable sent
	UnrchSnd6   int64 // ICMPv6 unreachable sent
	Invalid4    int64 // ICMPv4 invalid messages
	Invalid6    int64 // ICMPv6 invalid messages
	TimeoutSnd4 int64 // ICMPv4 TTL timeouts sent
	TimeoutSnd6 int64 // ICMPv6 TTL timeouts sent
	TimeoutRcv4 int64 // ICMPv4 TTL timeouts received
	TimeoutRcv6 int64 // ICMPv6 TTL timeouts received
	Drops4      int64 // ICMPv4 messages dropped
	Drops6      int64 // ICMPv6 messages dropped
}

type TCPStat struct {
	Active       int64 // connecting
	Passive      int64 // listening
	ChecksumErrs int64 // bad checksums
	Est          int64 // current established
	EstClo       int64 // established but closed
	EstRst       int64 // established but RST
	EstTo        int64 // established but timeout
	Con          int64 // current connected
	ConFail      int64 // failed connect attempts
	PortFail     int64 // failed port reservations
	RcvErrs      int64 // invalid recv segments
	AckDrop      int64 // acks dropped
	SynDrop      int64 // syns dropped
	Rcv          int64 // segments received
	Snd          int64 // segments sent
	SndErrs      int64 // segment send errors
	Retrans      int64 // retransmissions
	Timeouts     int64 // connection timeouts
	Drops        int64 // drops by max inflight threshold
}

type UDPStat struct {
	ChecksumErrs int64 // bad checksums
	RcvErrs      int64 // recv errors
	SndErrs      int64 // send errors
	Snd          int64 // packets sent
	Rcv          int64 // packets received
	PortFail     int64 // unknown port
	Drops        int64 // rcv buffer errors
}

type NetStat struct {
	NICStat
	IPStat
	IPFwdStat
	ICMPStat
	TCPStat
	UDPStat
}

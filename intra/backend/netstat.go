// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

// NICStat is a collection of network interface statistics for the current tunnel.
type NICStat struct {
	Rx        string // bytes received
	RxPkts    int64  // packets received
	Tx        string // bytes sent
	TxPkts    int64  // packets sent
	Invalid   int64  // invalid packets
	L4Unknown int64  // unknown l4 packets
	L3Unknown int64  // unknown l3 packets
	L4Drops   int64  // l4 drops
	Drops     int64  // drops
}

type NICInfo struct {
	Name        string
	HwAddr      string
	Addrs       string
	Mtu         int32
	Up          bool
	Running     bool
	Promisc     bool
	Lo          bool
	Arp         int32
	Forwarding4 bool
	Forwarding6 bool
}

// IPFwdStat is a collection of IP forwarding statistics for the current tunnel.
type IPFwdStat struct {
	Errs     int64 // errors
	Unrch    int64 // unreachable
	NoRoute  int64 // no route
	NoHop    int64 // no endpoint
	PTB      int64 // packet too big
	Timeouts int64 // TTL timeouts
	Drops    int64 // drops
}

// IPStat is a collection of IP statistics for the current tunnel.
type IPStat struct {
	InvalidDst  int64 // invalid destination addresses
	InvalidSrc  int64 // invalid source addresses
	InvalidFrag int64 // invalid fragments
	InvalidPkt  int64 // invalid packets
	Errs        int64 // packet errors
	Rcv         int64 // packets received from l2
	Snd         int64 // packets sent to l4
	ErrRcv      int64 // packet receive errors from l2
	ErrSnd      int64 // packet send errors to l4
}

// ICMPStat is a collection of ICMP statistics for the current tunnel.
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

// TCPStat is a collection of TCP statistics for the current tunnel.
type TCPStat struct {
	Active      int64 // connecting
	Passive     int64 // listening
	Est         int64 // current established
	EstClo      int64 // established but closed
	EstRst      int64 // established but RST
	EstTo       int64 // established but timeout
	Con         int64 // current connected
	ConFail     int64 // failed connect attempts
	PortFail    int64 // failed port reservations
	SynDrop     int64 // syns dropped
	AckDrop     int64 // acks dropped
	ErrChecksum int64 // bad checksums
	ErrRcv      int64 // invalid recv segments
	ErrSnd      int64 // segment send errors
	Rcv         int64 // segments received
	Snd         int64 // segments sent
	Retrans     int64 // retransmissions
	Timeouts    int64 // connection timeouts
	Drops       int64 // drops by max inflight threshold
}

// UDPStat is a collection of UDP statistics for the current tunnel.
type UDPStat struct {
	ErrChecksum int64 // bad checksums
	ErrRcv      int64 // recv errors
	ErrSnd      int64 // send errors
	Snd         int64 // packets sent
	Rcv         int64 // packets received
	PortFail    int64 // unknown port
	Drops       int64 // rcv buffer errors
}

type RDNSInfo struct {
	Open         bool
	Debug        bool
	Looping      bool
	Slowdown     bool
	Transparency bool

	Dialer4    bool
	Dialer6    bool
	DialerOpts string
	TunMode    string

	DNSPreferred string
	DNSDefault   string
	DNSSystem    string
	DNS          string

	ProxiesHas4   bool
	ProxiesHas6   bool
	ProxyLastOKMs int64
	ProxySinceMs  int64
	Proxies       string

	OpenConnsTCP  string
	OpenConnsUDP  string
	OpenConnsICMP string
}

// ref: github.com/google/gops/blob/35c854fb84a/agent/agent.go
type GoStat struct {
	Alloc      string // bytes allocated and not yet freed
	TotalAlloc string // total bytes allocated in aggregate
	Sys        string // bytes obtained from system
	Lookups    int64  // number of pointer lookups
	Mallocs    int64  // number of mallocs
	Frees      int64  // number of frees

	HeapAlloc    string // bytes allocated on heap
	HeapSys      string // heap obtained from system
	HeapIdle     string // bytes in idle spans
	HeapInuse    string // bytes in non-idle span
	HeapReleased string // bytes released to the OS
	HeapObjects  int64  // total number of allocated objects

	StackInuse  string // bytes used by stack allocator
	StackSys    string // bytes obtained from system for stack allocator
	MSpanInuse  string // mspan allocs
	MSpanSys    string // bytes obtained from system for mspan structures
	MCacheInuse string // mcache structures
	MCacheSys   string // bytes obtained from system for mcache structures
	BuckHashSys string // bytes used by the profiling bucket hash table

	EnableGC      bool   // GC enabled
	DebugGC       bool   // GC debug
	GCSys         string // bytes used for garbage collection system metadata
	OtherSys      string // bytes used for off-heap allocations
	NextGC        string // target heap size of the next GC
	LastGC        string // last run in heap
	PauseSecs     int64  // total STW pause time
	NumGC         int32  // number of GC runs
	NumForcedGC   int32  // number of forced GC runs
	GCCPUFraction string // fraction of CPU time used by GC

	NumGoroutine int64 // number of goroutines
	NumCgo       int64 // number of cgo calls
	NumCPU       int64 // number of CPUs
}

// NetStat is a collection of network engine statistics.
type NetStat struct {
	NICSt  NICStat
	NICIn  NICInfo
	IPSt   IPStat
	FWDSt  IPFwdStat
	ICMPSt ICMPStat
	TCPSt  TCPStat
	UDPSt  UDPStat
	RDNSIn RDNSInfo
	GOSt   GoStat
}

// NIC returns the network interface statistics.
func (n *NetStat) NIC() *NICStat { return &n.NICSt }

// NICI returns the network interface info.
func (n *NetStat) NICINFO() *NICInfo { return &n.NICIn }

// IP returns the IP statistics.
func (n *NetStat) IP() *IPStat { return &n.IPSt }

// FWD returns the IP forwarding statistics.
func (n *NetStat) FWD() *IPFwdStat { return &n.FWDSt }

// ICMP returns the ICMP statistics.
func (n *NetStat) ICMP() *ICMPStat { return &n.ICMPSt }

// TCP returns the TCP statistics.
func (n *NetStat) TCP() *TCPStat { return &n.TCPSt }

// UDP returns the UDP statistics.
func (n *NetStat) UDP() *UDPStat { return &n.UDPSt }

// RDNS returns the RDNS settings / info.
func (n *NetStat) RDNSINFO() *RDNSInfo { return &n.RDNSIn }

// GO returns the Go runtime statistics.
func (n *NetStat) GO() *GoStat { return &n.GOSt }

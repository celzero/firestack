// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wg

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"testing"
)

func TestIsNetworkUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", want: false},
		{name: "host unreachable", err: syscall.EHOSTUNREACH, want: true},
		{name: "network unreachable", err: syscall.ENETUNREACH, want: true},
		{name: "address unavailable", err: syscall.EADDRNOTAVAIL, want: true},
		{name: "family unsupported", err: syscall.EAFNOSUPPORT, want: true},
		{name: "wrapped", err: fmt.Errorf("wrapped: %w", syscall.EADDRNOTAVAIL), want: true},
		{name: "other", err: errors.New("other"), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isNetworkUnavailable(test.err); got != test.want {
				t.Fatalf("isNetworkUnavailable(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestIPv4MappedEndpointUsesIPv4(t *testing.T) {
	mapped := netip.MustParseAddrPort("[::ffff:192.0.2.1]:51820")
	v4 := netip.MustParseAddrPort("192.0.2.1:51820")

	if isIPv6(mapped) {
		t.Fatal("IPv4-mapped IPv6 address classified as IPv6")
	}
	if got := normalizeAddrPort(mapped); got != v4 {
		t.Fatalf("normalizeAddrPort(%v) = %v, want %v", mapped, got, v4)
	}
	if got := (&StdNetEndpoint{v4: normalizeAddrPort(mapped)}).get(); got != v4 {
		t.Fatalf("endpoint.get() = %v, want %v", got, v4)
	}
	if got := addrport(asEndpoint2(mapped)); got != v4 {
		t.Fatalf("addrport(mapped) = %v, want %v", got, v4)
	}
}

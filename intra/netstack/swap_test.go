// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestSwapAfterDisposeReplacesEndpoint(t *testing.T) {
	first, err := os.CreateTemp("", "netstack-swap-first")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(first.Name())
	defer first.Close()

	endpoint, err := NewEndpoint(int(first.Fd()), 1500, &testSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Dispose()

	magic, ok := endpoint.(*magiclink)
	if !ok {
		t.Fatalf("expected *magiclink, got %T", endpoint)
	}

	raw, _ := magic.get()
	if err := endpoint.Dispose(); err != nil {
		t.Fatal(err)
	}

	second, err := os.CreateTemp("", "netstack-swap-second")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(second.Name())
	defer second.Close()

	if err := endpoint.Swap(int(second.Fd()), 1500); err != nil {
		t.Fatal(err)
	}

	if got, _ := magic.get(); got == raw {
		t.Fatalf("endpoint was not replaced after disposed-fd swap: %p", got)
	}
	if got := magic.Stat().Fd; got != int(second.Fd()) {
		t.Fatalf("current fd = %d, want %d", got, second.Fd())
	}
}

func TestWritePacketsReturnsNoSuchFileAfterDispose(t *testing.T) {
	file, err := os.CreateTemp("", "netstack-write-invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	defer file.Close()

	endpoint, err := NewEndpoint(int(file.Fd()), 1500, &testSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Dispose()

	if err := endpoint.Dispose(); err != nil {
		t.Fatal(err)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{0}),
	})
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	defer pkts.DecRef()

	n, terr := endpoint.WritePackets(pkts)
	if n != 0 {
		t.Fatalf("written packets = %d, want 0", n)
	}
	if _, ok := terr.(*tcpip.ErrNoSuchFile); !ok {
		t.Fatalf("WritePackets error = %T (%v), want *tcpip.ErrNoSuchFile", terr, terr)
	}
}

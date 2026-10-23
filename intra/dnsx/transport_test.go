// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestWritePrefixedLargePayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 2736)
	var dst bytes.Buffer

	written, err := writePrefixed(&dst, payload, len(payload))
	if err != nil {
		t.Fatalf("writePrefixed() error = %v", err)
	}
	if written != len(payload) {
		t.Fatalf("writePrefixed() wrote %d payload bytes; want %d", written, len(payload))
	}

	got := dst.Bytes()
	if len(got) != len(payload)+2 {
		t.Fatalf("framed length = %d; want %d", len(got), len(payload)+2)
	}
	if prefix := int(binary.BigEndian.Uint16(got[:2])); prefix != len(payload) {
		t.Fatalf("length prefix = %d; want %d", prefix, len(payload))
	}
	if !bytes.Equal(got[2:], payload) {
		t.Fatal("framed payload does not match input")
	}
}

func TestWritePrefixedRejectsInvalidLength(t *testing.T) {
	for _, length := range []int{-1, 4, 0x10000} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			var dst bytes.Buffer
			if _, err := writePrefixed(&dst, []byte{1, 2, 3}, length); err == nil {
				t.Fatalf("writePrefixed() with length %d succeeded; want error", length)
			}
			if dst.Len() != 0 {
				t.Fatalf("writer received %d bytes for invalid length", dst.Len())
			}
		})
	}
}

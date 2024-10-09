// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT

// from: https://github.com/bepass-org/warp-plus/blob/19ac233cc/iputils/iputils.go

package core

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net/netip"
	"time"
)

// RandomIPFromPrefix returns a random IP from the provided CIDR prefix.
// Supports IPv4 and IPv6. Does not support mapped inputs.
func RandomIPFromPrefix(cidr netip.Prefix) (netip.Addr, error) {
	startingAddress := cidr.Masked().Addr()
	if startingAddress.Is4In6() {
		return netip.Addr{}, errors.New("mapped v4 addresses not supported")
	}

	prefixLen := cidr.Bits()
	if prefixLen == -1 {
		return netip.Addr{}, fmt.Errorf("invalid cidr: %s", cidr)
	}

	// Initialise rand number generator
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Find the bit length of the Host portion of the provided CIDR
	// prefix
	hostLen := big.NewInt(int64(startingAddress.BitLen() - prefixLen))

	// Find the max value for our random number
	max := new(big.Int).Exp(big.NewInt(2), hostLen, nil)

	// Generate the random number
	randInt := new(big.Int).Rand(rng, max)

	// Get the first address in the CIDR prefix in 16-bytes form
	startingAddress16 := startingAddress.As16()

	// Convert the first address into a decimal number
	startingAddressInt := new(big.Int).SetBytes(startingAddress16[:])

	// Add the random number to the decimal form of the starting address
	// to get a random address in the desired range
	randomAddressInt := new(big.Int).Add(startingAddressInt, randInt)

	// Convert the random address from decimal form back into netip.Addr
	randomAddress, ok := netip.AddrFromSlice(randomAddressInt.FillBytes(make([]byte, 16)))
	if !ok {
		return netip.Addr{}, fmt.Errorf("failed to generate random IP from CIDR: %s", cidr)
	}

	// Unmap any mapped v4 addresses before return
	return randomAddress.Unmap(), nil
}

// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.
package tunnel

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"

	"github.com/eycorsican/go-tun2socks/common/log"
	_ "github.com/eycorsican/go-tun2socks/common/log/simple" // Import simple log for the side effect of making logs printable.
)

const vpnMtu = 1500

// MakeTunFile returns an os.File object from a TUN file descriptor `fd`.
// The returned os.File holds a separate reference to the underlying file,
// so the file will not be closed until both `fd` and the os.File are
// separately closed.  (UNIX only.)
func Dup(fd int) (int, error) {
	if fd < 0 {
		return -1, errors.New("Must provide a valid TUN file descriptor")
	}

	// Make a copy of `fd` so that os.File's finalizer doesn't close `fd`.
	newfd, err := unix.Dup(fd)
	if err != nil {
		return -1, err
	}

	return newfd, nil
}

// ProcessInputPackets reads packets from a TUN device `tun` and writes them to `tunnel`.
func ProcessInputPackets(tunnel Tunnel, tun *os.File) {
	buffer := make([]byte, vpnMtu)
	for tunnel.IsConnected() {
		len, err := tun.Read(buffer)
		if err != nil {
			log.Warnf("Failed to read packet from TUN: %v", err)
			continue
		}
		if len == 0 {
			log.Infof("Read EOF from TUN")
			continue
		}
		tunnel.Write(buffer)
	}
}

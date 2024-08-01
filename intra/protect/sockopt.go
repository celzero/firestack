// Copyright (c) 2024 RethinkDNS and its authors.
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

package protect

import (
	"syscall"

	"github.com/celzero/firestack/intra/log"
)

const (
	defaultKeepIdle = 45
	defaultKeepCnt = 5
	defaultKeepIntvl = 1
)

func SetKeepAliveConfig(network, addr string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		sock := int(fd)
		if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, defaultKeepIdle); err!=nil {
			log.E("set TCP_KEEPIDLE failed: %v", err)
		}
		if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, defaultKeepIntvl); err!=nil {
			log.E("set TCP_KEEPINTVL failed: %v", err)
		}
		if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, defaultKeepCnt); err!=nil {
			log.E("set TCP_KEEPCNT failed: %v", err)
		}
	})
}

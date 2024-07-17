// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2018 The gVisor Authors.
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package netstack

import (
	"fmt"
	"syscall"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
)

// stopFd is an eventfd used to signal the stop of a dispatcher.
type stopFd struct {
	efd int
}

func newStopFd() (stopFd, error) {
	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		return stopFd{efd: -1}, fmt.Errorf("failed to create eventfd: %w", err)
	}
	return stopFd{efd: efd}, nil
}

// stop writes to the eventfd and notifies the dispatcher to stop. It does not
// block.
func (s *stopFd) stop() {
	increment := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	if n, err := unix.Write(s.efd, increment); n != len(increment) || err != nil {
		// There are two possible errors documented in eventfd(2) for writing:
		// 1. We are writing 8 bytes and not 0xffffffffffffff, thus no EINVAL.
		// 2. stop is only supposed to be called once, it can't reach the limit,
		// thus no EAGAIN.
		panic(fmt.Sprintf("write(efd) = (%d, %s), want (%d, nil)", n, err, len(increment)))
	}
}

type fds struct {
	stopFd stopFd
	tunFd  int
}

func newTun(fd int) (*fds, error) {
	stopFd, err := newStopFd()
	if err != nil {
		return nil, err
	}
	return &fds{stopFd, fd}, nil
}

func (f *fds) ok() bool {
	return f != nil && f.tun() != invalidfd
}

func (f *fds) eve() int {
	if f != nil {
		return f.stopFd.efd
	}
	return invalidfd
}

func (f *fds) tun() int {
	if f != nil {
		return f.tunFd
	}
	return invalidfd
}

func (f *fds) stop() {
	if f.ok() {
		f.stopFd.stop()
		err := syscall.Close(f.tunFd)
		log.I("ns: dispatch: fds: stop: eve(%d) tun(%d); err? %v", f.stopFd.efd, f.tunFd, err)
	} else {
		log.W("ns: dispatch: fds: stop: no-op")
	}
}

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
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
)

var invalidFds = &fds{stopFd: stopFd{efd: invalidfd}, tunFd: invalidfd}

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
func (s *stopFd) stop() error {
	if s.efd == invalidfd || s.efd <= 2 {
		return nil
	}
	increment := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	if n, err := unix.Write(s.efd, increment); n != len(increment) || err != nil {
		// There are two possible errors documented in eventfd(2) for writing:
		// 1. We are writing 8 bytes and not 0xffffffffffffff, thus no EINVAL.
		// 2. stop is only supposed to be called once, it can't reach the limit,
		// thus no EAGAIN.
		return fmt.Errorf("write(efd) = (%d, %s), want (%d, nil)", n, err, len(increment))
	}
	return nil
}

type fds struct {
	stopFd stopFd
	tunFd  int

	read      atomic.Int64 // number of bytes read
	written   atomic.Int64 // number of bytes written
	since     atomic.Int64 // when fd was created
	death     atomic.Int64 // age in millis
	lastRead  atomic.Int64 // last read time in millis
	lastWrite atomic.Int64 // last write time in millis

	closed atomic.Bool
	once   sync.Once // ensures that stop() is called only once
}

// Takes ownership of fd, which must be a valid TUN file descriptor.
// Never returns nil, but may return an invalid fds (with tunFd = -1).
func newTun(fd int) (*fds, error) {
	if fd == invalidfd {
		return invalidFds, nil
	}
	err := unix.SetNonblock(fd, true)
	if err != nil {
		clos(fd)
		return invalidFds, err
	}
	stopFd, err := newStopFd()
	if err != nil {
		clos(fd)
		return invalidFds, err
	}
	f := &fds{
		stopFd: stopFd,
		tunFd:  fd,
	}
	f.since.Store(time.Now().UnixMilli())
	return f, nil
}

func (f *fds) ok() bool {
	return f != nil && f.tun() != invalidfd && !f.closed.Load()
}

func (f *fds) eve() int {
	if f != nil && f.stopFd.efd > 2 {
		return f.stopFd.efd
	}
	return invalidfd
}

func (f *fds) tun() int {
	if f != nil && f.tunFd > 2 {
		return f.tunFd
	}
	return invalidfd
}

func (f *fds) stop() {
	if f.ok() {
		f.once.Do(func() {
			defer f.closed.Store(true)

			now := time.Now().UnixMilli()
			f.death.Store(now)
			age := now - f.since.Load()

			err1 := f.stopFd.stop()
			err2 := syscall.Close(f.tunFd)
			logeif(err1)("ns: dispatch: fds: stop: eve(%d) tun(%d) age(%s); errs? %v %v",
				f.stopFd.efd, f.tunFd, core.FmtMillis(age), err1, err2)
		})
	} else {
		log.W("ns: dispatch: fds: stop: no-op")
	}
}

func (f *fds) String() string {
	return strconv.Itoa(f.tunFd)
}

func clos(fd int) {
	if fd > 0 || fd != invalidfd {
		_ = syscall.Close(fd)
	}
}

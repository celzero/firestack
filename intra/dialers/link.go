// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

var ipProto *core.Volatile[string] = core.NewVolatile(settings.IP46)

func Use4() bool {
	d := true // by default, use4
	switch ipProto.Load() {
	case settings.IP6:
		return false
	case settings.IP4:
		fallthrough
	case settings.IP46:
		return true
	default:
		return d
	}
}

func Use6() bool {
	d := false // by default, use4 instead
	switch ipProto.Load() {
	case settings.IP4:
		return false
	case settings.IP6:
		fallthrough
	case settings.IP46:
		return true
	default:
		return d
	}
}

// p must be one of settings.IP4, settings.IP6, or settings.IP46
func IPProtos(ippro string) (diff bool) {
	switch ippro {
	case settings.IP4:
		fallthrough
	case settings.IP6:
		fallthrough
	case settings.IP46:
		diff = ipProto.Swap(ippro) != ippro
	default:
		log.D("dialers: ips: invalid protos %s; use existing: %s", ippro, ipProto.Load())
		return
	}
	log.I("dialers: ips: protos set to %s; diff? %t", ippro, diff)
	return
}

// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT
//
//    Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

package wg

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

// from: github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/android/backend/Statistics.java
// from: github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java#L119

var (
	errNoSuchPeer    = errors.New("wg: no such peer")
	errAllStatsNotOK = errors.New("wg: all stats not OK")

	baTtl    = 30 * time.Second
	baNegTtl = 2 * time.Second
	ba       = core.NewBarrier2[*ifstats, uint64](context.TODO(), "wg.s.bar", baTtl, baNegTtl)
)

// peerstats represents the statistics for a peer.
type peerstats struct {
	RxBytes                    int64
	TxBytes                    int64
	LatestHandshakeEpochMillis int64
}

// ifstats holds the statistics for peers.
type ifstats struct {
	o           string
	stats       map[string]peerstats
	lastTouched time.Time
}

func (s *ifstats) String() string {
	if s == nil {
		return "<nil>"
	}

	o := s.o
	d := s.lastTouched.UnixMilli()
	rx := s.TotalRx()
	tx := s.TotalTx()
	hdshk := s.LatestRecentHandshake()
	return fmt.Sprintf("ifstats{o: %s, lastTouched: %d, rx: %d, tx: %d, lastOK: %d}",
		o, d, rx, tx, hdshk)
}

// newStats creates a new Statistics instance.
func newStats(owner string) *ifstats {
	return &ifstats{
		o:           owner,
		stats:       make(map[string]peerstats),
		lastTouched: time.Now(),
	}
}

// add adds a new peer's statistics to the map.
func (s *ifstats) add(key string, rx, tx, latestHandshake int64) bool {
	if settings.Debug {
		log.VV("wg: ReadStats: %s: add %s, %d, %d, %d", s.o, key, rx, tx, latestHandshake)
	}
	s.stats[key] = peerstats{RxBytes: rx, TxBytes: tx, LatestHandshakeEpochMillis: latestHandshake}
	return latestHandshake > 0
}

// IsStale checks if the statistics are older than 15 minutes.
func (s *ifstats) IsStale() bool {
	return time.Since(s.lastTouched) > 15*time.Minute
}

// Peer retrieves the statistics for a specific peer.
func (s *ifstats) Peer(key string) (peerstats, error) {
	if stats, ok := s.stats[key]; ok {
		return stats, nil
	}
	return peerstats{}, errNoSuchPeer
}

// Peers returns all the keys (peers) in the statistics map.
func (s *ifstats) Peers() []string {
	keys := make([]string, 0, len(s.stats))
	for key := range s.stats {
		keys = append(keys, key)
	}
	return keys
}

// TotalRx calculates the total received bytes.
func (s *ifstats) TotalRx() int64 {
	var total int64
	for _, stats := range s.stats {
		total += stats.RxBytes
	}
	return total
}

// TotalTx calculates the total transmitted bytes.
func (s *ifstats) TotalTx() int64 {
	var total int64
	for _, stats := range s.stats {
		total += stats.TxBytes
	}
	return total
}

func (s *ifstats) LatestRecentHandshake() int64 {
	least := int64(0)
	for _, stats := range s.stats {
		least = max(least, stats.LatestHandshakeEpochMillis)
	}
	if settings.Debug {
		log.VV("wg: ReadStats: %s: LatestRecentHandshake: %s, Peers: %d",
			s.o, core.FmtUnixMillisAsPeriod(least), len(s.stats))
	}
	return least
}

func ReadStats(who string, id uint64, cfn core.Work[string]) *ifstats {
	v, err := ba.DoIt(id, func() (*ifstats, error) {
		cfg, err := cfn()
		if err != nil || len(cfg) <= 0 {
			log.W("wg: ReadStats: %s: %s: ipcget: %v", who, strconv.FormatUint(id, 16), err)
			return nil, err
		}
		return readStats(who, cfg)
	})
	if err != nil { // v is nil when ba.Do timesout or no handshake yet
		log.W("wg: ReadStats: %s nil for %s, err: %v", who, strconv.FormatUint(id, 16), err)
	}
	return v
}

// readStats parses a configuration string and returns a Statistics instance.
func readStats(who, config string) (*ifstats, error) {
	stats := newStats(who)
	var key string
	var rx, tx, latestHandshakeMillis int64
	var anyStatOK bool

	// see: github.com/WireGuard/wireguard-go/blob/12269c27/device/uapi.go#L51
	lines := strings.Split(config, "\n")
	n := len(lines)
	k := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			if key != "" {
				k++
				anyStatOK = stats.add(key, rx, tx, latestHandshakeMillis) || anyStatOK
			}
			rx = 0
			tx = 0
			latestHandshakeMillis = 0
			key = line[11:]
		} else if strings.HasPrefix(line, "rx_bytes=") {
			if key == "" {
				continue
			}
			rx, _ = strconv.ParseInt(line[9:], 10, 64)
		} else if strings.HasPrefix(line, "tx_bytes=") {
			if key == "" {
				continue
			}
			tx, _ = strconv.ParseInt(line[9:], 10, 64)
		} else if strings.HasPrefix(line, "last_handshake_time_sec=") {
			if key == "" {
				continue
			}
			sec, _ := strconv.ParseInt(line[24:], 10, 64)
			latestHandshakeMillis += sec * 1000
		} else if strings.HasPrefix(line, "last_handshake_time_nsec=") {
			if key == "" {
				continue
			}
			nsec, _ := strconv.ParseInt(line[25:], 10, 64)
			latestHandshakeMillis += nsec / 1000000
		}
	}
	if key != "" {
		k++
		anyStatOK = stats.add(key, rx, tx, latestHandshakeMillis) || anyStatOK
	}
	stats.lastTouched = time.Now()

	if settings.Debug {
		log.V("wg: ReadStats: %s: %d peers, %d lines, any OK? %t", who, k, n, anyStatOK)
	}
	if !anyStatOK {
		return stats, errAllStatsNotOK // negative ttl on barrier
	}

	return stats, nil
}

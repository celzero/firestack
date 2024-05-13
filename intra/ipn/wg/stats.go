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
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
)

// from: github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/android/backend/Statistics.java
// from: github.com/WireGuard/wireguard-android/blob/4ba87947ae/tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java#L119

var (
	errNoSuchPeer = errors.New("no such peer")
	ba            = core.NewBarrier[*ifstats](30 * time.Second)
)

// peerstats represents the statistics for a peer.
type peerstats struct {
	RxBytes                    int64
	TxBytes                    int64
	LatestHandshakeEpochMillis int64
}

// ifstats holds the statistics for peers.
type ifstats struct {
	stats       map[string]peerstats
	lastTouched time.Time
}

// newStats creates a new Statistics instance.
func newStats() *ifstats {
	return &ifstats{
		stats:       make(map[string]peerstats),
		lastTouched: time.Now(),
	}
}

// add adds a new peer's statistics to the map.
func (s *ifstats) add(key string, rx, tx, latestHandshake int64) {
	s.stats[key] = peerstats{RxBytes: rx, TxBytes: tx, LatestHandshakeEpochMillis: latestHandshake}
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
	return least
}

func ReadStats(id, config string) *ifstats {
	v, _ := ba.Do(id, func() (*ifstats, error) {
		return readStats(config), nil
	})
	if v == nil { // unlikely
		log.W("wg: ReadStats: nil for %s", id)
		return nil
	}
	return v.Val
}

// readStats parses a configuration string and returns a Statistics instance.
func readStats(config string) *ifstats {
	stats := newStats()
	var key string
	var rx, tx, latestHandshakeMillis int64

	// see: github.com/WireGuard/wireguard-go/blob/12269c27/device/uapi.go#L51
	lines := strings.Split(config, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			if key != "" {
				stats.add(key, rx, tx, latestHandshakeMillis)
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
		stats.add(key, rx, tx, latestHandshakeMillis)
	}
	stats.lastTouched = time.Now()
	return stats
}

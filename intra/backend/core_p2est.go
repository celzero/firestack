// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import (
	"context"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/core"
)

// 5 samples is the min recommended for P2 quantile estimation.
const minQsamples = 5

// Quants contains a timestamped snapshot of P2 quantile estimates.
type Quants struct {
	P25   int64
	P50   int64
	P75   int64
	P99   int64
	Since int64
}

// P2Quantiles estimates the 25th, 50th, 75th, and 99th percentiles.
type P2Quantiles struct {
	mu     sync.Mutex
	closed bool
	cancel context.CancelFunc
	p25    core.P2QuantileEstimator
	p50    core.P2QuantileEstimator
	p75    core.P2QuantileEstimator
	p99    core.P2QuantileEstimator
	since  int64
}

// NewP2Quantiles creates a new set of P2 quantile estimators.
func NewP2Quantiles() *P2Quantiles {
	p := &P2Quantiles{}
	p.Reset()
	return p
}

// Add adds a sample to each quantile estimator.
func (p *P2Quantiles) Add(v int64) {
	if p == nil {
		return
	}

	p.mu.Lock()
	if p.closed {
		p.closed = false
		p.resetLocked()
	}
	p25 := p.p25
	p50 := p.p50
	p75 := p.p75
	p99 := p.p99
	p.mu.Unlock()

	x := float64(v)
	p25.Add(x)
	p50.Add(x)
	p75.Add(x)
	p99.Add(x)
}

// P25 returns the estimated 25th percentile.
func (p *P2Quantiles) P25() int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	return p.p25.Get()
}

// P50 returns the estimated 50th percentile.
func (p *P2Quantiles) P50() int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	return p.p50.Get()
}

// P75 returns the estimated 75th percentile.
func (p *P2Quantiles) P75() int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	return p.p75.Get()
}

// P99 returns the estimated 99th percentile.
func (p *P2Quantiles) P99() int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	return p.p99.Get()
}

// Close stops the current estimators.
func (p *P2Quantiles) Close() {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
}

// Reset stops the current estimators and starts a fresh set.
func (p *P2Quantiles) Reset() Quants {
	if p == nil {
		return Quants{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resetLocked()
}

func (p *P2Quantiles) resetLocked() Quants {
	ctx, cancel := context.WithCancel(context.Background())
	p25 := core.NewP2QuantileEstimator(ctx, minQsamples, 0.25)
	p50 := core.NewP2QuantileEstimator(ctx, minQsamples, 0.50)
	p75 := core.NewP2QuantileEstimator(ctx, minQsamples, 0.75)
	p99 := core.NewP2QuantileEstimator(ctx, minQsamples, 0.99)
	now := time.Now().UnixMilli()

	q := p.allLocked()
	if p.cancel != nil {
		p.cancel()
	}

	p.cancel = cancel
	p.p25 = p25
	p.p50 = p50
	p.p75 = p75
	p.p99 = p99
	p.since = now

	return q
}

// All returns all quantile estimates and the reset timestamp.
func (p *P2Quantiles) All() Quants {
	if p == nil {
		return Quants{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allLocked()
}

func (p *P2Quantiles) allLocked() Quants {
	q := Quants{}
	if p.closed {
		return q
	}
	if p.p25 != nil {
		q.P25 = p.p25.Get()
	}
	if p.p50 != nil {
		q.P50 = p.p50.Get()
	}
	if p.p75 != nil {
		q.P75 = p.p75.Get()
	}
	if p.p99 != nil {
		q.P99 = p.p99.Get()
	}
	q.Since = p.since
	return q
}

// Since returns the Unix time in milliseconds when this set was created or reset.
func (p *P2Quantiles) Since() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.since
}

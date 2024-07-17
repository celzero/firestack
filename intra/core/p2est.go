// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"math"
	"slices"
	"sync"
)

// from: github.com/celzero/rethink-app/main/app/src/main/java/com/celzero/bravedns/util/P2QuantileEstimation.kt
// details: aakinshin.net/posts/p2-quantile-estimator/
// orig impl: github.com/AndreyAkinshin/perfolizer p2.cs
type p2 struct {
	mu    sync.RWMutex
	ctx   context.Context
	p     float64      // percentile
	u     int64        // sample size
	mid   int64        // u / 2
	n     []int64      // marker positions
	ns    []float64    // desired marker positions
	q     []float64    // marker heights
	count int64        // total sampled so far
	addc  chan float64 // add sample
}

// P2QuantileEstimator is an interface for the P2 quantile estimator.
type P2QuantileEstimator interface {
	// Add a sample to the estimator.
	Add(float64)
	// Get the estimation for p.
	Get() int64
	// Get the percentile, p.
	P() float64
}

var _ P2QuantileEstimator = (*p2)(nil)

// NewP50Estimator returns a new P50 (median) estimator.
func NewP50Estimator(ctx context.Context) *p2 {
	// calibrate: go.dev/play/p/Ry1i61XqzgB
	// 31 worked best amid wild latency fluctuations
	// using 11 for lower overhead; 5 is the default
	return NewP2QuantileEstimator(ctx, 11, 0.5)
}

// NewP90Estimator returns a new estimator with percentile p.
func NewP2QuantileEstimator(ctx context.Context, samples int64, probability float64) *p2 {
	// total samples, typically 5; higher sample size improves accuracy for
	// lower percentiles (p50) at the expense of computational cost;
	// for higher percentiles (p90+), even sample size as low as 5 works fine.
	mid := int64(math.Floor(float64(samples) / 2.0))
	p := &p2{
		ctx:   ctx,
		p:     probability,
		u:     samples,
		mid:   mid,
		n:     make([]int64, samples),
		ns:    make([]float64, samples),
		q:     make([]float64, samples),
		count: 0,
		addc:  make(chan float64, samples),
	}
	go p.run()
	return p
}

// P returns the percentile, p.
func (est *p2) P() float64 {
	return est.p
}

// Add a sample to the estimator.
// www.cse.wustl.edu/~jain/papers/ftp/psqr.pdf (p. 1078)
func (est *p2) Add(x float64) {
	select {
	case est.addc <- x:
	case <-est.ctx.Done():
	default:
	}
}

func (est *p2) run() {
	for {
		select {
		case x := <-est.addc:
			est.add(x)
		case <-est.ctx.Done():
			return
		}
	}
}

func (est *p2) add(x float64) {
	est.mu.Lock()
	defer est.mu.Unlock()

	defer func() {
		est.count += 1
	}()

	if est.count < est.u {
		est.q[est.count] = x

		if est.count+1 == est.u {
			slices.Sort(est.q)

			t := est.u - 1 // 0 index
			for i := int64(0); i <= t; i++ {
				est.n[i] = i
			}

			// divide p into mid no of equal segments
			// p => 0.5, u = 11, t = 10, mid = 5; pmid => 0.1
			pmid := est.p / float64(est.mid)
			for i := int64(0); i <= est.mid; i++ {
				density := pmid * float64(i)
				est.ns[i] = density * float64(t)
			}

			rem := t - est.mid // the rest
			s := 1.0 - est.p   // left-over probability
			// divide q into rem no of equal segments
			// q => 0.5, u = 10, mid = 5, rem = 5; smid => 0.5
			smid := s / float64(rem)
			for i := int64(1); i <= rem; i++ {
				// assign i-th portion of smid to dns[mid+i]
				// [mid+1] => .6, [mid+2] => .7, [mid+3] => .8,
				// [mid+4] => .9, [mid+5] => 1
				density := (smid * float64(i)) + est.p
				// assign t-th portion of dns[mid+i] to ns[mid+i]
				// [mid+1] => 6, [mid+2] => 7, [mid+3] => 8,
				// [mid+4] => 9, [mid+5] => 10
				est.ns[est.mid+i] = density * float64(t)
			}
		}
		return
	}

	var k int64
	if x < est.q[0] {
		est.q[0] = x // update min
		k = 0
	} else if x > est.q[est.u-1] {
		est.q[est.u-1] = x // update max
		k = est.u - 2
	} else {
		k = est.u - 2
		for i := int64(1); i <= est.u-2; i++ {
			if x < est.q[i] {
				k = i - 1
				break
			}
		}
	}

	for i := k + 1; i < est.u; i++ {
		est.n[i]++
	}

	// go.dev/play/p/wL0hHYIB5DT
	// for i := 0; i < est.u; i++ {
	//	est.ns[i] += est.dns[i]
	// }

	// go.dev/play/p/yY23exf-KXh
	factor := float64(est.count) / float64(est.count-1)
	for i := int64(0); i < est.u; i++ { // update desired marker positions
		est.ns[i] *= factor
	}

	for i := int64(1); i < est.u-1; i++ { // update intermediatories
		d := est.ns[i] - float64(est.n[i])

		if (d >= 1 && est.n[i+1]-est.n[i] > 1) || (d <= -1 && est.n[i-1]-est.n[i] < -1) {
			dInt := sign2int(d)
			qs := est.parabolicLocked(i, float64(dInt))
			if est.q[i-1] < qs && qs < est.q[i+1] {
				est.q[i] = qs
			} else {
				est.q[i] = est.linearLocked(i, dInt)
			}
			est.n[i] += dInt
		}
	}
}

// parabolicLocked computes the parabolic estimate.
func (est *p2) parabolicLocked(i int64, d float64) float64 {
	qi := est.q[i]
	qij := est.q[i+1]
	qih := est.q[i-1]
	ni := float64(est.n[i])
	nij := float64(est.n[i+1])
	nih := float64(est.n[i-1])
	return qi +
		(d/(nij-nih))*
			(((ni-nih+d)*(qij-qi)/(nij-ni))+
				((nij-ni-d)*(qi-qih)/(ni-nih)))
}

// linearLocked computes the linear estimate.
func (est *p2) linearLocked(i int64, d int64) float64 {
	df := float64(d)
	qi := est.q[i]
	qd := est.q[i+d]
	ni := float64(est.n[i])
	nd := float64(est.n[i+d])
	return qi + (df*(qd-qi))/(nd-ni)
}

// Get the estimation for p.
func (est *p2) Get() int64 {
	est.mu.RLock()
	defer est.mu.RUnlock()

	c := est.count

	if c == 0 {
		return 0
	}

	if c > est.u {
		ms := est.q[est.mid] * 1000
		return int64(ms)
	}

	slices.Sort(est.q[:c]) // go.dev/play/p/sCIM4AB1t6n
	index := int(float64(c-1) * est.p)
	ms := est.q[index] * 1000
	return int64(ms)
}

// sign2int returns the sign of the float64 as an int.
func sign2int(d float64) int64 {
	if d < 0 {
		return -1
	} else if d > 0 {
		return 1
	} else {
		return 0
	}
}

// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"math"
	"slices"
	"sync/atomic"
)

// from: github.com/celzero/rethink-app/main/app/src/main/java/com/celzero/bravedns/util/P2QuantileEstimation.kt
// details: aakinshin.net/posts/p2-quantile-estimator/
// orig impl: github.com/AndreyAkinshin/perfolizer p2.cs
type p2 struct {
	p     float64      // percentile
	u     int64        // sample size
	mid   int64        // u / 2
	n     []int64      // marker positions
	ns    []float64    // desired marker positions
	q     []float64    // marker heights
	count atomic.Int64 // total sampled so far
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
func NewP50Estimator() *p2 {
	// calibrate: go.dev/play/p/Ry1i61XqzgB
	// 31 worked best amid wild latency fluctuations
	// using 11 for lower overhead; 5 is the default
	return NewP2QuantileEstimator(11, 0.5)
}

// NewP90Estimator returns a new estimator with percentile p.
func NewP2QuantileEstimator(samples int64, probability float64) *p2 {
	// total samples, typically 5; higher sample size improves accuracy for
	// lower percentiles (p50) at the expense of computational cost;
	// for higher percentiles (p90+), even sample size as low as 5 works fine.
	mid := int64(math.Floor(float64(samples) / 2.0))
	return &p2{
		p:     probability,
		u:     samples,
		mid:   mid,
		n:     make([]int64, samples),
		ns:    make([]float64, samples),
		q:     make([]float64, samples),
		count: atomic.Int64{},
	}
}

// P returns the percentile, p.
func (est *p2) P() float64 {
	return est.p
}

// Add a sample to the estimator.
// www.cse.wustl.edu/~jain/papers/ftp/psqr.pdf (p. 1078)
func (est *p2) Add(x float64) {
	if est.count.Load() < est.u {
		cnt := est.count.Add(1)
		est.q[cnt-1] = x

		if cnt == est.u {
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

	cnt := est.count.Add(1)
	cnt = cnt - 1 // old

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
	factor := float64(cnt) / float64(cnt-1)
	for i := int64(0); i < est.u; i++ { // update desired marker positions
		est.ns[i] *= factor
	}

	for i := int64(1); i < est.u-1; i++ { // update intermediatories
		d := est.ns[i] - float64(est.n[i])

		if (d >= 1 && est.n[i+1]-est.n[i] > 1) || (d <= -1 && est.n[i-1]-est.n[i] < -1) {
			dInt := sign2int(d)
			qs := est.parabolic(i, float64(dInt))
			if est.q[i-1] < qs && qs < est.q[i+1] {
				est.q[i] = qs
			} else {
				est.q[i] = est.linear(i, dInt)
			}
			est.n[i] += dInt
		}
	}
}

// parabolic computes the parabolic estimate.
func (est *p2) parabolic(i int64, d float64) float64 {
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

// linear computes the linear estimate.
func (est *p2) linear(i int64, d int64) float64 {
	df := float64(d)
	qi := est.q[i]
	qd := est.q[i+d]
	ni := float64(est.n[i])
	nd := float64(est.n[i+d])
	return qi + (df*(qd-qi))/(nd-ni)
}

// Get the estimation for p.
func (est *p2) Get() int64 {
	c := est.count.Load()

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

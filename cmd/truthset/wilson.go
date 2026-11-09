package main

import "math"

// wilson is the Wilson score interval for k successes in n trials at 95%
// confidence (z = 1.96), the interval that behaves at the edges a
// vulnerability scanner lives at: 35 of 35 gives (0.901, 1.0), not (1.0,
// 1.0), which is the honest statement about a perfect run on a small set
// -- the rule of three in a formula. n == 0 is (0, 0): no trials, no claim.
func wilson(k, n int) (lo, hi float64) {
	if n <= 0 {
		return 0, 0
	}
	const z = 1.959963984540054
	p := float64(k) / float64(n)
	nn := float64(n)
	denom := 1 + z*z/nn
	centre := (p + z*z/(2*nn)) / denom
	half := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn)) / denom
	lo, hi = centre-half, centre+half
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

// Package rank implements the confidence scoring used to rank candidate origin
// IPs. Scoring is a pure function of the weights of the techniques that agreed
// on a given IP, with no I/O and no dependencies outside the standard library.
package rank

// Score computes the noisy-OR aggregate of a set of technique weights:
//
//	score = 1 - ∏ (1 - wᵢ)
//
// The noisy-OR rule treats each technique as an independent piece of evidence:
// several weak signals accumulate into a stronger one, but the result is
// naturally bounded and never exceeds 1. Weights outside the [0,1] range are
// clamped before combination. An empty input yields 0.
func Score(weights []float64) float64 {
	product := 1.0
	for _, w := range weights {
		product *= 1.0 - clamp01(w)
	}
	return 1.0 - product
}

// clamp01 constrains v to the closed interval [0,1].
func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

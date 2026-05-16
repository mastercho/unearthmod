package rank

import (
	"math"
	"testing"
)

const tol = 1e-9

func approx(a, b float64) bool { return math.Abs(a-b) < tol }

func TestScoreEmpty(t *testing.T) {
	if got := Score(nil); got != 0 {
		t.Fatalf("Score(nil) = %v, want 0", got)
	}
	if got := Score([]float64{}); got != 0 {
		t.Fatalf("Score([]) = %v, want 0", got)
	}
}

func TestScoreSingle(t *testing.T) {
	if got := Score([]float64{0.9}); !approx(got, 0.9) {
		t.Fatalf("Score([0.9]) = %v, want 0.9", got)
	}
}

func TestScoreNoisyOr(t *testing.T) {
	// 1 - (1-0.9)(1-0.65) = 1 - 0.1*0.35 = 1 - 0.035 = 0.965
	if got := Score([]float64{0.9, 0.65}); !approx(got, 0.965) {
		t.Fatalf("Score([0.9,0.65]) = %v, want 0.965", got)
	}
}

func TestScoreOrderIndependent(t *testing.T) {
	a := Score([]float64{0.3, 0.5, 0.85})
	b := Score([]float64{0.85, 0.3, 0.5})
	if !approx(a, b) {
		t.Fatalf("order changed result: %v vs %v", a, b)
	}
}

func TestScoreSaturates(t *testing.T) {
	if got := Score([]float64{1.0, 0.5}); !approx(got, 1.0) {
		t.Fatalf("Score with weight 1.0 = %v, want 1.0", got)
	}
}

func TestScoreClamps(t *testing.T) {
	// negative weights clamp to 0 and contribute nothing
	if got := Score([]float64{-0.5, 0.6}); !approx(got, 0.6) {
		t.Fatalf("Score([-0.5,0.6]) = %v, want 0.6", got)
	}
	// weights above 1 clamp to 1 and saturate the score
	if got := Score([]float64{1.7}); !approx(got, 1.0) {
		t.Fatalf("Score([1.7]) = %v, want 1.0", got)
	}
}

func TestScoreBounds(t *testing.T) {
	cases := [][]float64{
		{0.1, 0.2, 0.3, 0.4, 0.5},
		{0.99, 0.99, 0.99},
		{0.01},
		{-1, 2, 0.5},
	}
	for _, c := range cases {
		got := Score(c)
		if got < 0 || got > 1 {
			t.Fatalf("Score(%v) = %v, out of [0,1]", c, got)
		}
	}
}

func TestScoreMonotonic(t *testing.T) {
	// adding a positive-weight technique never lowers the score
	base := Score([]float64{0.4, 0.5})
	more := Score([]float64{0.4, 0.5, 0.3})
	if more < base {
		t.Fatalf("adding evidence lowered score: %v < %v", more, base)
	}
}

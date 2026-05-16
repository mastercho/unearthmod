//go:build e2e

// Package unearth's end-to-end test: actually runs Discover against a real
// public target over the network. Disabled by default — guarded by the
// `e2e` build tag so the standard `go test ./...` remains fully offline and
// deterministic.
//
// To run:
//
//	go test -tags=e2e ./pkg/unearth -run TestE2E -v
//
// The test passes if Discover returns a usable *Result with no engine-level
// error. Per-technique errors (rate-limited crt.sh, no Censys key, etc.)
// are expected and recorded on Result.Errors; the test does NOT assert
// any particular candidate, only that the pipeline completed end to end
// against the live internet.
package unearth

import (
	"context"
	"testing"
	"time"

	"github.com/unearth-tool/unearth/pkg/techniques"
)

func TestE2E_DiscoverExampleCom(t *testing.T) {
	opts := DefaultOptions()
	// Generous overall budget — ct_fingerprint's TimeoutOverride is 2m and
	// crtsh's is 90s; an honest passive run needs room for both. Past 5m
	// is a real problem.
	opts.OverallTimeout = 5 * time.Minute
	opts.PerTechniqueTimeout = 30 * time.Second
	opts.NoCache = true

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := Discover(ctx, "example.com", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if res.Target != "example.com" {
		t.Errorf("Target = %q", res.Target)
	}
	if res.Timestamp.IsZero() {
		t.Error("Timestamp not set")
	}
	t.Logf("e2e Discover: cdn=%q candidates=%d errors=%d warnings=%d",
		res.CDNDetected, len(res.Candidates), len(res.Errors), len(res.Warnings))
	for _, c := range res.Candidates {
		t.Logf("  %-40s score=%.3f corrob=%d %v",
			c.IP, c.Score, c.Corroboration,
			func() []string {
				ns := make([]string, len(c.Techniques))
				for i, h := range c.Techniques {
					ns[i] = h.Name
				}
				return ns
			}())
	}
	for _, e := range res.Errors {
		t.Logf("  err[%s] reason=%q: %s", e.Technique, e.Reason, e.Err)
	}
}

func TestE2E_ActiveTier(t *testing.T) {
	opts := DefaultOptions()
	opts.Tier = techniques.TierActive
	opts.OverallTimeout = 2 * time.Minute
	opts.PerTechniqueTimeout = 30 * time.Second
	opts.NoCache = true

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := Discover(ctx, "example.com", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	t.Logf("e2e --active example.com: cdn=%q candidates=%d errors=%d warnings=%d",
		res.CDNDetected, len(res.Candidates), len(res.Errors), len(res.Warnings))
	for _, c := range res.Candidates {
		names := make([]string, len(c.Techniques))
		for i, h := range c.Techniques {
			names[i] = h.Name
		}
		t.Logf("  %-40s score=%.3f corrob=%d %v", c.IP, c.Score, c.Corroboration, names)
	}
	for _, e := range res.Errors {
		t.Logf("  err[%s] reason=%q: %s", e.Technique, e.Reason, e.Err)
	}
}

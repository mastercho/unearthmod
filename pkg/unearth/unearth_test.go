package unearth

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unearth-tool/unearth/pkg/cdn"
	"github.com/unearth-tool/unearth/pkg/rank"
	"github.com/unearth-tool/unearth/pkg/techniques"
)

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	if o.Tier != techniques.TierPassive {
		t.Errorf("default Tier = %v, want passive", o.Tier)
	}
	if o.Concurrency != 10 {
		t.Errorf("default Concurrency = %d, want 10", o.Concurrency)
	}
	if o.PerTechniqueTimeout <= 0 {
		t.Error("default PerTechniqueTimeout must be positive")
	}
	if o.OverallTimeout <= 0 {
		t.Error("default OverallTimeout must be positive")
	}
}

// fakeTech is a minimal in-memory technique driven by the test.
type fakeTech struct {
	name       string
	weight     float64
	tier       techniques.Tier
	requiresK  bool
	candidates []techniques.Candidate
	err        error
	delay      time.Duration
	doPanic    bool
	ranOnce    atomic.Int32
}

func (f *fakeTech) Name() string           { return f.name }
func (f *fakeTech) Tier() techniques.Tier  { return f.tier }
func (f *fakeTech) RequiresAPIKey() bool   { return f.requiresK }
func (f *fakeTech) DefaultWeight() float64 { return f.weight }

func (f *fakeTech) Run(ctx context.Context, _ string, _ techniques.RunOptions) ([]techniques.Candidate, error) {
	f.ranOnce.Add(1)
	if f.doPanic {
		panic("kaboom")
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.candidates, nil
}

func withSelector(t *testing.T, techs ...techniques.Technique) {
	t.Helper()
	prev := techniqueSelector
	techniqueSelector = func(maxTier techniques.Tier) []techniques.Technique {
		var out []techniques.Technique
		for _, x := range techs {
			if x.Tier() <= maxTier {
				out = append(out, x)
			}
		}
		return out
	}
	// Also stub CDN detection so the test suite is fully offline.
	prevDet := cdnDetect
	cdnDetect = func(context.Context, string, *http.Client) (cdn.Detection, error) {
		return cdn.Detection{}, nil
	}
	t.Cleanup(func() {
		techniqueSelector = prev
		cdnDetect = prevDet
	})
}

func testOpts() Options {
	o := DefaultOptions()
	o.OverallTimeout = 5 * time.Second
	o.PerTechniqueTimeout = 500 * time.Millisecond
	o.NoCache = true
	return o
}

func TestDiscover_BasicGroupingAndScoring(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "a", weight: 0.5, candidates: []techniques.Candidate{
			{IP: "203.0.113.1", Evidence: "a-evidence"},
		}},
		&fakeTech{name: "b", weight: 0.5, candidates: []techniques.Candidate{
			{IP: "203.0.113.1", Evidence: "b-evidence"},
			{IP: "203.0.113.2", Evidence: "lone"},
		}},
	)
	res, err := Discover(context.Background(), "example.test", testOpts())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("Candidates: want 2, got %d (%+v)", len(res.Candidates), res.Candidates)
	}
	top := res.Candidates[0]
	if top.IP != "203.0.113.1" {
		t.Errorf("top IP: want .1, got %s", top.IP)
	}
	if top.Status != "candidate" {
		t.Errorf("top Status: want candidate, got %q", top.Status)
	}
	if top.Corroboration != 2 {
		t.Errorf("Corroboration: want 2, got %d", top.Corroboration)
	}
	if top.SingleSource {
		t.Errorf("SingleSource should be false for 2-source hit")
	}
	wantScore := rank.Score([]float64{0.5, 0.5}) // 0.75
	if math.Abs(top.Score-wantScore) > 1e-9 {
		t.Errorf("Score: want %g, got %g", wantScore, top.Score)
	}
	lone := res.Candidates[1]
	if lone.IP != "203.0.113.2" {
		t.Errorf("lone IP: want .2, got %s", lone.IP)
	}
	if !lone.SingleSource || lone.Corroboration != 1 {
		t.Errorf("lone: SingleSource=%v Corroboration=%d", lone.SingleSource, lone.Corroboration)
	}
	if math.Abs(lone.Score-0.5) > 1e-9 {
		t.Errorf("lone Score: want 0.5, got %g", lone.Score)
	}
}

func TestDiscover_DeduplicatesTechniqueContributionPerIP(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "banner_grab", weight: 0.45, candidates: []techniques.Candidate{
			{IP: "203.0.113.10", Evidence: "port 80"},
			{IP: "203.0.113.10", Evidence: "port 443"},
			{IP: "203.0.113.10", Evidence: "port 22"},
		}},
		&fakeTech{name: "ct_fingerprint", weight: 0.7, candidates: []techniques.Candidate{
			{IP: "203.0.113.10", Evidence: "cert"},
		}},
	)
	res, err := Discover(context.Background(), "example.test", testOpts())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Candidates) != 1 {
		t.Fatalf("Candidates: %+v", res.Candidates)
	}
	got := res.Candidates[0]
	if got.Corroboration != 2 {
		t.Fatalf("Corroboration = %d, want 2 distinct techniques (got %+v)", got.Corroboration, got.Techniques)
	}
	if got.Status != "candidate" {
		t.Fatalf("Status = %q, want candidate", got.Status)
	}
	if len(got.Techniques) != 2 {
		t.Fatalf("Techniques = %+v, want one hit per technique", got.Techniques)
	}
	wantScore := rank.Score([]float64{0.45, 0.7})
	if math.Abs(got.Score-wantScore) > 1e-9 {
		t.Fatalf("Score = %g, want %g", got.Score, wantScore)
	}
}

func TestDiscover_SortOrder(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "a", weight: 0.3, candidates: []techniques.Candidate{
			{IP: "203.0.113.10"}, {IP: "203.0.113.20"},
		}},
		&fakeTech{name: "b", weight: 0.9, candidates: []techniques.Candidate{
			{IP: "203.0.113.20"}, // gets the higher-scoring hit
		}},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	if res.Candidates[0].IP != "203.0.113.20" {
		t.Errorf("sort by score desc: want .20 first, got %s", res.Candidates[0].IP)
	}
	// Same-score tiebreak by IP asc — induce by giving both .30 and .40 only
	// from technique 'a' with weight 0.3.
	withSelector(t,
		&fakeTech{name: "a", weight: 0.3, candidates: []techniques.Candidate{
			{IP: "203.0.113.40"}, {IP: "203.0.113.30"},
		}},
	)
	res, _ = Discover(context.Background(), "x", testOpts())
	if res.Candidates[0].IP != "203.0.113.30" || res.Candidates[1].IP != "203.0.113.40" {
		t.Errorf("tiebreak by IP asc: got %v", []string{res.Candidates[0].IP, res.Candidates[1].IP})
	}
}

func TestDiscover_PerTechniqueTimeout(t *testing.T) {
	slow := &fakeTech{name: "slow", weight: 0.5, delay: 5 * time.Second}
	fast := &fakeTech{name: "fast", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.5"}}}
	withSelector(t, slow, fast)
	opts := testOpts()
	opts.PerTechniqueTimeout = 50 * time.Millisecond
	start := time.Now()
	res, _ := Discover(context.Background(), "x", opts)
	if time.Since(start) > 2*time.Second {
		t.Errorf("per-tech timeout did not cut slow: %v", time.Since(start))
	}
	var foundSlow bool
	for _, e := range res.Errors {
		if e.Technique == "slow" {
			foundSlow = true
			if e.Reason != "timeout" {
				t.Errorf("slow reason: want timeout, got %q (err %q)", e.Reason, e.Err)
			}
		}
	}
	if !foundSlow {
		t.Error("slow technique should appear in Errors")
	}
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "203.0.113.5" {
		t.Errorf("fast technique should still produce its candidate, got %+v", res.Candidates)
	}
}

func TestDiscover_MissingAPIKeySkipped(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "needs_key", weight: 0.9, requiresK: true},
		&fakeTech{name: "open", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.7"}}},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	var skipped TechniqueErr
	for _, e := range res.Errors {
		if e.Technique == "needs_key" {
			skipped = e
		}
	}
	if skipped.Reason != "missing_api_key" {
		t.Errorf("needs_key reason: want missing_api_key, got %q", skipped.Reason)
	}
	if len(res.Candidates) != 1 {
		t.Errorf("open technique still produces results, got %d", len(res.Candidates))
	}
}

func TestDiscover_RecordsZeroCandidateTechniqueRun(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "empty", weight: 0.5},
		&fakeTech{name: "hit", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.8"}}},
	)
	res, err := Discover(context.Background(), "x", testOpts())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	got := map[string]TechniqueRun{}
	for _, r := range res.TechniqueRuns {
		got[r.Technique] = r
	}
	if r := got["empty"]; r.Status != "ok" || r.Candidates != 0 {
		t.Fatalf("empty run = %+v, want ok with 0 candidates", r)
	}
	if r := got["hit"]; r.Status != "ok" || r.Candidates != 1 {
		t.Fatalf("hit run = %+v, want ok with 1 candidate", r)
	}
}

func TestDiscover_RecordsDiagnosticsWithoutRankingThem(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "host_header", weight: 0.85, candidates: []techniques.Candidate{{
			Metadata: map[string]any{"diagnostic": map[string]any{
				"event":       "baseline",
				"message":     "baseline fetched",
				"status_code": 200,
				"url":         "https://example.test/",
			}},
		}}},
	)
	res, err := Discover(context.Background(), "example.test", testOpts())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Candidates) != 0 {
		t.Fatalf("diagnostic should not become ranked candidate: %+v", res.Candidates)
	}
	if len(res.TechniqueRuns) != 1 || res.TechniqueRuns[0].Candidates != 0 || len(res.TechniqueRuns[0].Diagnostics) != 1 {
		t.Fatalf("diagnostic run not recorded correctly: %+v", res.TechniqueRuns)
	}
	if got := res.TechniqueRuns[0].Diagnostics[0]; got.Event != "baseline" || got.StatusCode != 200 {
		t.Fatalf("diagnostic metadata wrong: %+v", got)
	}
}

func TestDiscover_PreservesValidationMetadata(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "host_header", weight: 0.85, candidates: []techniques.Candidate{
			{
				IP:       "203.0.113.88",
				Evidence: "confirmed",
				Metadata: map[string]any{
					"validation": map[string]any{
						"status":       "confirmed",
						"technique":    "host_header",
						"method":       "host_header",
						"url":          "https://203.0.113.88:443/",
						"scheme":       "https",
						"port":         443,
						"score":        0.82,
						"html_score":   0.74,
						"cert_score":   1.0,
						"header_score": 0.33,
						"title_match":  true,
						"threshold":    0.60,
					},
				},
			},
		}},
	)
	res, err := Discover(context.Background(), "x", testOpts())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Candidates) != 1 {
		t.Fatalf("Candidates: %+v", res.Candidates)
	}
	if res.Candidates[0].Status != "confirmed" {
		t.Fatalf("Status = %q, want confirmed", res.Candidates[0].Status)
	}
	v := res.Candidates[0].Validation
	if v == nil || v.Status != "confirmed" || v.Technique != "host_header" || v.Port != 443 {
		t.Fatalf("validation not preserved: %+v", v)
	}
	if v.Score != 0.82 || v.HTMLScore != 0.74 || v.CertScore != 1.0 || v.HeaderScore != 0.33 || !v.TitleMatch {
		t.Fatalf("validation scores not preserved: %+v", v)
	}
}

func TestHasKeyFor_FaviconHashUsesShodanOrCensys(t *testing.T) {
	if !hasKeyFor("favicon_hash", techniques.APIKeys{ShodanAPIKey: "shodan"}) {
		t.Fatal("favicon_hash should run with Shodan key")
	}
	if !hasKeyFor("favicon_hash", techniques.APIKeys{CensysPlatformPAT: "censys"}) {
		t.Fatal("favicon_hash should run with Censys PAT")
	}
	if hasKeyFor("favicon_hash", techniques.APIKeys{}) {
		t.Fatal("favicon_hash should skip with neither Shodan nor Censys")
	}
}

func TestDiscover_FiltersCDNCandidatesAtAggregation(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "leaky", weight: 0.9, candidates: []techniques.Candidate{
			{IP: "104.31.74.201"},
			{IP: "203.0.113.7"},
		}},
	)
	res, err := Discover(context.Background(), "x", testOpts())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "203.0.113.7" {
		t.Fatalf("want only non-CDN candidate, got %+v", res.Candidates)
	}
}

func TestDiscover_FiltersPrivateCandidatesAtAggregation(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "private-leak", weight: 0.9, candidates: []techniques.Candidate{
			{IP: "10.230.0.20"},
			{IP: "198.51.100.7"},
		}},
	)
	res, err := Discover(context.Background(), "x", testOpts())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "198.51.100.7" {
		t.Fatalf("want only public candidate, got %+v", res.Candidates)
	}
}

func TestDiscover_PanicContained(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "boom", weight: 0.5, doPanic: true},
		&fakeTech{name: "ok", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.9"}}},
	)
	res, err := Discover(context.Background(), "x", testOpts())
	if err != nil {
		t.Fatalf("panic should not escape Discover: %v", err)
	}
	var boomErr TechniqueErr
	for _, e := range res.Errors {
		if e.Technique == "boom" {
			boomErr = e
		}
	}
	if boomErr.Err == "" {
		t.Error("panicking technique should produce a TechniqueErr")
	}
	if len(res.Candidates) != 1 {
		t.Errorf("non-panicking technique still works, got %d candidates", len(res.Candidates))
	}
}

func TestDiscover_BudgetExhaustedReason(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "broke", weight: 0.5, err: techniques.ErrBudgetExhausted},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	if len(res.Errors) != 1 || res.Errors[0].Reason != "budget_exhausted" {
		t.Errorf("want budget_exhausted reason, got %+v", res.Errors)
	}
}

func TestDiscover_ErrorsSortedByTechniqueName(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "zeta", weight: 0.5, err: errors.New("z")},
		&fakeTech{name: "alpha", weight: 0.5, err: errors.New("a")},
		&fakeTech{name: "mike", weight: 0.5, err: errors.New("m")},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	if len(res.Errors) != 3 {
		t.Fatalf("want 3 errors, got %d", len(res.Errors))
	}
	want := []string{"alpha", "mike", "zeta"}
	for i, w := range want {
		if res.Errors[i].Technique != w {
			t.Errorf("Errors[%d]: want %s, got %s", i, w, res.Errors[i].Technique)
		}
	}
}

func TestDiscover_ConcurrencyBoundRespected(t *testing.T) {
	var live, peak atomic.Int64
	makeTech := func(name string) *fakeTech {
		return &fakeTech{
			name:   name,
			weight: 0.5,
			delay:  40 * time.Millisecond,
		}
	}
	tech := func(name string) *fakeTech {
		f := makeTech(name)
		f.candidates = []techniques.Candidate{{IP: "203.0.113." + name}}
		return f
	}
	_ = tech
	// Use a wrapper that bumps live/peak around Run.
	wrap := func(name string) techniques.Technique {
		return &countingTech{fakeTech: fakeTech{name: name, weight: 0.5, delay: 40 * time.Millisecond}, live: &live, peak: &peak}
	}
	withSelector(t, wrap("a"), wrap("b"), wrap("c"), wrap("d"))
	opts := testOpts()
	opts.Concurrency = 2
	opts.PerTechniqueTimeout = 2 * time.Second
	_, _ = Discover(context.Background(), "x", opts)
	if peak.Load() > 2 {
		t.Errorf("concurrency bound violated: peak %d > 2", peak.Load())
	}
}

type countingTech struct {
	fakeTech
	live, peak *atomic.Int64
}

func (c *countingTech) Run(ctx context.Context, target string, opts techniques.RunOptions) ([]techniques.Candidate, error) {
	n := c.live.Add(1)
	defer c.live.Add(-1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	return c.fakeTech.Run(ctx, target, opts)
}

func TestDiscover_ContextAlreadyCancelled(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "n", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.5"}}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Discover(ctx, "x", testOpts())
	if err == nil {
		t.Error("expected engine error on pre-cancelled context")
	}
}

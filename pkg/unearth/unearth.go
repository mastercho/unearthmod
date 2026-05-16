// Package unearth is the public library API for origin-IP discovery. It
// exposes the Discover entrypoint and the result types that the CLI and the
// MCP server consume.
package unearth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/internal/httpclient"
	"github.com/unearth-tool/unearth/internal/ratelimit"
	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
	"github.com/unearth-tool/unearth/pkg/config"
	"github.com/unearth-tool/unearth/pkg/rank"
	"github.com/unearth-tool/unearth/pkg/techniques"
)

// Options configures a discovery run.
type Options struct {
	// Tier is the maximum technique aggression to run. Lower tiers are
	// always included: TierActive runs passive and active techniques.
	Tier techniques.Tier
	// APIKeys holds optional third-party credentials.
	APIKeys techniques.APIKeys
	// BudgetCaps limits paid-API usage for the run.
	BudgetCaps techniques.BudgetCaps
	// NoCache bypasses the result cache entirely.
	NoCache bool
	// Refresh ignores cached entries but writes fresh results back.
	Refresh bool
	// Concurrency is the number of techniques run in parallel.
	Concurrency int
	// PerTechniqueTimeout bounds how long a single technique may run.
	PerTechniqueTimeout time.Duration
	// OverallTimeout bounds the whole discovery run.
	OverallTimeout time.Duration
}

// DefaultOptions returns Options with conservative defaults: passive tier only,
// ten concurrent techniques, a 30s per-technique timeout and a 5m overall
// timeout.
func DefaultOptions() Options {
	return Options{
		Tier:                techniques.TierPassive,
		Concurrency:         10,
		PerTechniqueTimeout: 30 * time.Second,
		OverallTimeout:      5 * time.Minute,
	}
}

// TechniqueHit records one technique's contribution to a candidate IP.
type TechniqueHit struct {
	Name     string  `json:"name"`
	Weight   float64 `json:"weight"`
	Evidence string  `json:"evidence"`
}

// ScoredIP is a single ranked candidate origin IP.
type ScoredIP struct {
	// IP is the candidate origin address.
	IP string `json:"candidate_ip"`
	// Score is the noisy-OR confidence in [0,1].
	Score float64 `json:"score"`
	// Corroboration is the number of distinct techniques that found this IP.
	Corroboration int `json:"corroboration"`
	// SingleSource is true when exactly one technique found this IP. It is a
	// deliberate, separate signal from Score: a lone weak hit and a lone
	// strong hit can both warrant caution that the numeric score alone hides.
	SingleSource bool `json:"single_source"`
	// Techniques lists every technique that contributed, with its weight.
	Techniques []TechniqueHit `json:"techniques"`
}

// TechniqueErr records a technique that failed or was skipped during a run.
type TechniqueErr struct {
	Technique string `json:"technique"`
	Err       string `json:"error"`
	// Reason is a short machine-readable cause, e.g. "missing_api_key",
	// "timeout" or "budget_exhausted". It may be empty.
	Reason string `json:"reason,omitempty"`
}

// Result is the full output of a discovery run.
type Result struct {
	Target      string         `json:"target"`
	CDNDetected string         `json:"cdn_detected,omitempty"`
	Candidates  []ScoredIP     `json:"candidates"`
	Timestamp   time.Time      `json:"timestamp"`
	Errors      []TechniqueErr `json:"errors,omitempty"`
	// Warnings is a list of non-fatal issues — config warnings from
	// LoadWeights, cache-open failures, CDN-detection errors. Surfaced so
	// the CLI and the MCP server can show them without inspecting Errors,
	// which is reserved for per-technique failures.
	Warnings []string `json:"warnings,omitempty"`
}

// Discover runs origin-IP discovery against a single target and returns
// ranked candidates. The returned error is non-nil only when the engine
// itself could not start the run (e.g. ctx was already cancelled);
// per-technique failures are recorded on Result.Errors.
func Discover(ctx context.Context, target string, opts Options) (*Result, error) {
	opts = withDefaults(opts)

	overallCtx, cancel := context.WithTimeout(ctx, opts.OverallTimeout)
	defer cancel()

	if err := overallCtx.Err(); err != nil {
		return nil, fmt.Errorf("unearth: context: %w", err)
	}

	result := &Result{Target: target}

	// Weights (and any unknown-technique warnings).
	weights, warns, err := config.LoadWeights("")
	if err != nil {
		result.Warnings = append(result.Warnings, "config: "+err.Error())
	}
	result.Warnings = append(result.Warnings, warns...)

	// Cache (best-effort).
	var cstore techniques.CacheStore
	if !opts.NoCache {
		c, err := cache.Open("")
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("cache: open failed (%s); running without cache", err))
		} else {
			cstore = c
			defer c.Close()
		}
	}

	// HTTP client, rate limiter, budget.
	hc := httpclient.New(httpclient.Options{})
	limiter := ratelimit.NewLimiter(map[string]ratelimit.EndpointConfig{
		"crtsh": {RPS: 0.5, Burst: 2}, // crt.sh is a free community service
		"dns":   {RPS: 20, Burst: 20},
	})
	budget := ratelimit.NewBudget(opts.BudgetCaps)

	// CDN detection — non-fatal.
	if det, err := cdnDetect(overallCtx, target, hc); err == nil {
		result.CDNDetected = det.CDN
	} else {
		result.Warnings = append(result.Warnings, "cdn detect: "+err.Error())
		// det is still useful (may have matched some signals before error).
		result.CDNDetected = det.CDN
	}

	// Build the technique RunOptions once; it is read-only across goroutines.
	runOpts := techniques.RunOptions{
		HTTPClient:  hc,
		APIKeys:     opts.APIKeys,
		Cache:       cstore,
		RateLimiter: limiter,
		BudgetCaps:  opts.BudgetCaps,
		Budget:      budget,
		NoCache:     opts.NoCache,
		Refresh:     opts.Refresh,
	}

	// Select techniques, filter for missing keys.
	selected := techniqueSelector(opts.Tier)
	var runnable []techniques.Technique
	for _, t := range selected {
		if t.RequiresAPIKey() && !hasKeyFor(t.Name(), opts.APIKeys) {
			result.Errors = append(result.Errors, TechniqueErr{
				Technique: t.Name(),
				Err:       techniques.ErrMissingAPIKey.Error(),
				Reason:    "missing_api_key",
			})
			continue
		}
		runnable = append(runnable, t)
	}

	// Run in parallel, bounded by Concurrency.
	type techResult struct {
		t          techniques.Technique
		candidates []techniques.Candidate
		err        error
	}
	results := make([]techResult, len(runnable))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i, t := range runnable {
		wg.Add(1)
		i, t := i, t
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-overallCtx.Done():
				results[i] = techResult{t: t, err: overallCtx.Err()}
				return
			}
			defer func() { <-sem }()
			results[i] = runOne(overallCtx, t, target, runOpts, opts.PerTechniqueTimeout)
		}()
	}
	wg.Wait()

	// Fold results.
	groups := map[string]*ScoredIP{}
	for _, r := range results {
		if r.err != nil {
			result.Errors = append(result.Errors, TechniqueErr{
				Technique: r.t.Name(),
				Err:       r.err.Error(),
				Reason:    reasonForErr(r.err),
			})
			continue
		}
		w := resolveWeight(weights, r.t)
		for _, c := range r.candidates {
			g, ok := groups[c.IP]
			if !ok {
				g = &ScoredIP{IP: c.IP}
				groups[c.IP] = g
			}
			g.Techniques = append(g.Techniques, TechniqueHit{
				Name:     r.t.Name(),
				Weight:   w,
				Evidence: c.Evidence,
			})
		}
	}

	// Score and finalize.
	for _, g := range groups {
		ws := make([]float64, len(g.Techniques))
		for i, h := range g.Techniques {
			ws[i] = h.Weight
		}
		g.Score = rank.Score(ws)
		g.Corroboration = len(g.Techniques)
		g.SingleSource = g.Corroboration == 1
		sort.Slice(g.Techniques, func(i, j int) bool { return g.Techniques[i].Name < g.Techniques[j].Name })
		result.Candidates = append(result.Candidates, *g)
	}
	sort.Slice(result.Candidates, func(i, j int) bool {
		if result.Candidates[i].Score != result.Candidates[j].Score {
			return result.Candidates[i].Score > result.Candidates[j].Score
		}
		return result.Candidates[i].IP < result.Candidates[j].IP
	})
	sort.Slice(result.Errors, func(i, j int) bool {
		return result.Errors[i].Technique < result.Errors[j].Technique
	})

	result.Timestamp = time.Now().UTC()
	return result, nil
}

// runOne runs a single technique under a child context with the per-
// technique timeout, recovers from any panic the technique might throw, and
// returns a normalized techResult-shaped trio.
func runOne(
	ctx context.Context, t techniques.Technique, target string,
	opts techniques.RunOptions, timeout time.Duration,
) (out struct {
	t          techniques.Technique
	candidates []techniques.Candidate
	err        error
}) {
	out.t = t
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			out.candidates = nil
			out.err = fmt.Errorf("technique %s panicked: %v", t.Name(), r)
		}
	}()
	out.candidates, out.err = t.Run(tctx, target, opts)
	if out.err != nil && errors.Is(out.err, context.DeadlineExceeded) {
		// Surface DeadlineExceeded directly so reasonForErr maps it cleanly.
		out.err = context.DeadlineExceeded
	} else if out.err == nil && tctx.Err() != nil {
		out.err = tctx.Err()
	}
	return out
}

func withDefaults(opts Options) Options {
	d := DefaultOptions()
	if opts.Concurrency <= 0 {
		opts.Concurrency = d.Concurrency
	}
	if opts.PerTechniqueTimeout <= 0 {
		opts.PerTechniqueTimeout = d.PerTechniqueTimeout
	}
	if opts.OverallTimeout <= 0 {
		opts.OverallTimeout = d.OverallTimeout
	}
	return opts
}

func resolveWeight(w config.Weights, t techniques.Technique) float64 {
	if v, ok := w.Weight(t.Name()); ok {
		return v
	}
	return t.DefaultWeight()
}

func reasonForErr(err error) string {
	switch {
	case errors.Is(err, techniques.ErrMissingAPIKey):
		return "missing_api_key"
	case errors.Is(err, techniques.ErrBudgetExhausted):
		return "budget_exhausted"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return ""
	}
}

// techniqueSelector resolves the technique list for a given tier. The
// indirection lets tests inject fake techniques without polluting the
// global registry. Production code path is techniques.ByTier.
var techniqueSelector = techniques.ByTier

// cdnDetect is the indirection used by Discover to invoke CDN detection so
// tests can stub it offline without faking DNS and HTTP at the same time.
// Production code path is cdn.Detect.
var cdnDetect = cdn.Detect

// hasKeyFor reports whether opts.APIKeys carries credentials usable by the
// named technique. Used by the engine to skip key-required techniques
// before launching a goroutine.
func hasKeyFor(name string, k techniques.APIKeys) bool {
	switch name {
	case "censys_cert":
		return k.CensysAPIID != "" && k.CensysAPISecret != ""
	case "dns_history":
		return k.SecurityTrailsKey != "" || k.ViewDNSKey != ""
	case "shodan_cert":
		return k.ShodanAPIKey != ""
	default:
		// Unknown technique that declares RequiresAPIKey()==true: the
		// conservative answer is "we don't know what key it needs, so we
		// don't have one." The technique still gets a chance to defend
		// itself if a caller bypasses the engine's pre-filter.
		return false
	}
}

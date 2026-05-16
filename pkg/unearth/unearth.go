// Package unearth is the public library API for origin-IP discovery. It
// exposes the Discover entrypoint and the result types that the CLI and the
// MCP server consume.
package unearth

import (
	"context"
	"time"

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
}

// Discover runs origin-IP discovery against a single target and returns ranked
// candidates.
//
// TODO(packet-3): real orchestration — CDN detection, parallel technique
// execution, candidate grouping and ranking. This stub returns an empty result
// so the public API and its consumers compile against a stable signature.
func Discover(ctx context.Context, target string, opts Options) (*Result, error) {
	_ = ctx
	_ = opts
	return &Result{
		Target:    target,
		Timestamp: time.Now().UTC(),
	}, nil
}

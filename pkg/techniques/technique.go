// Package techniques defines the Technique interface that every origin-discovery
// method implements, the shared types techniques exchange with the
// orchestration engine, and the registry that tracks them.
package techniques

import (
	"context"
	"net/http"
	"time"
)

// Tier expresses how aggressive a technique is. The CLI gates techniques by
// tier so a user can control how much a run touches the target.
type Tier int

const (
	// TierPassive techniques never contact the target. They query third-party
	// services and public records only and are safe for any scope.
	TierPassive Tier = iota
	// TierActive techniques make direct requests to candidate IPs and grab
	// service banners. They touch the target but stay within most scopes.
	TierActive
	// TierAggressive techniques deliberately provoke origin leaks and may
	// violate strict scope rules.
	TierAggressive
)

// String returns the lowercase name of the tier.
func (t Tier) String() string {
	switch t {
	case TierPassive:
		return "passive"
	case TierActive:
		return "active"
	case TierAggressive:
		return "aggressive"
	default:
		return "unknown"
	}
}

// Candidate is a single origin-IP guess produced by a technique.
type Candidate struct {
	// IP is the candidate origin address, IPv4 or IPv6. The producing
	// technique is responsible for validating it.
	IP string
	// Evidence is human-readable proof of why this IP was surfaced,
	// e.g. "cert SHA256 abc123... via Censys".
	Evidence string
	// Metadata holds optional raw fragments from the underlying source.
	// It may be nil.
	Metadata map[string]any
}

// APIKeys holds optional third-party credentials. An empty field means the
// technique that depends on it is skipped rather than failed.
type APIKeys struct {
	CensysAPIID       string
	CensysAPISecret   string
	ShodanAPIKey      string
	SecurityTrailsKey string
	ViewDNSKey        string
}

// BudgetCaps limits the number of paid-API calls a single invocation may make.
type BudgetCaps struct {
	Censys         int
	Shodan         int
	SecurityTrails int
}

// CacheStore is the contract the SQLite cache (Packet 2) satisfies. Techniques
// depend on this interface so the techniques package never imports the cache
// implementation.
type CacheStore interface {
	// Get returns the cached value for key. hit reports whether a live
	// (unexpired) entry was found.
	Get(key string) (value []byte, hit bool, err error)
	// Set stores value under key with the given time-to-live.
	Set(key string, value []byte, ttl time.Duration) error
}

// RateLimiter is the contract the rate limiter (Packet 2) satisfies.
type RateLimiter interface {
	// Wait blocks until a call keyed by key is permitted or ctx is done.
	Wait(ctx context.Context, key string) error
	// Allow reports whether a call keyed by key is permitted right now
	// without blocking.
	Allow(key string) bool
}

// RunOptions carries everything a technique needs to execute a single run.
type RunOptions struct {
	// HTTPClient is the shared client techniques should use for HTTP work.
	HTTPClient *http.Client
	// APIKeys holds third-party credentials; fields may be empty.
	APIKeys APIKeys
	// Cache is the result cache. It may be nil when caching is disabled.
	Cache CacheStore
	// RateLimiter throttles outbound calls. It may be nil.
	RateLimiter RateLimiter
	// BudgetCaps limits paid-API usage for this invocation.
	BudgetCaps BudgetCaps
	// NoCache, when true, instructs techniques to bypass the cache entirely.
	NoCache bool
	// Refresh, when true, instructs techniques to ignore cached entries but
	// still write fresh results back to the cache.
	Refresh bool
}

// Technique is the extension point of unearth. Each technique is implemented
// in its own file in this package and registers itself in an init function.
type Technique interface {
	// Name is the stable, lowercase identifier of the technique, e.g. "crtsh".
	Name() string
	// Tier reports the technique's aggression level.
	Tier() Tier
	// RequiresAPIKey reports whether the technique needs credentials to run.
	// When true and the relevant key is absent, the engine skips it.
	RequiresAPIKey() bool
	// DefaultWeight is the technique's baseline reliability, in [0,1]. The
	// config layer may override this per technique; the engine resolves a
	// configured override first and falls back to this value.
	DefaultWeight() float64
	// Run executes the technique against a single target and returns the
	// candidate origin IPs it found.
	Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error)
}

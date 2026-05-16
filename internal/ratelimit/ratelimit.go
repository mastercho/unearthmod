// Package ratelimit provides per-endpoint rate limiting and per-invocation
// budget caps for paid APIs.
//
// The Limiter type implements techniques.RateLimiter using
// golang.org/x/time/rate token buckets keyed by an arbitrary string (the
// engine keys by API endpoint, e.g. "crtsh", "censys", "shodan"). A
// conservative default rate is used for unknown keys; per-key overrides may
// be registered at construction time so gentle community services like
// crt.sh can be throttled more aggressively than commercial APIs.
//
// The Budget type is independent of the rate limiter: it caps the total
// number of paid-API calls a single invocation may make, so a misconfigured
// loop cannot drain a user's Censys or Shodan credits.
package ratelimit

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/unearth-tool/unearth/pkg/techniques"
	"golang.org/x/time/rate"
)

// Defaults applied when no override is supplied.
const (
	// DefaultRPS is the default sustained calls-per-second for any endpoint
	// the caller has not overridden. It is intentionally conservative.
	DefaultRPS = 5.0
	// DefaultBurst is the default token-bucket burst size for any endpoint
	// the caller has not overridden.
	DefaultBurst = 5
)

// EndpointConfig overrides the default limit for a specific key.
type EndpointConfig struct {
	// RPS is the sustained tokens-per-second the bucket refills at.
	RPS float64
	// Burst is the maximum number of tokens the bucket can hold.
	Burst int
}

// Limiter is a per-key token-bucket rate limiter. Methods are safe for
// concurrent use.
type Limiter struct {
	mu        sync.Mutex
	buckets   map[string]*rate.Limiter
	overrides map[string]EndpointConfig
	defaultC  EndpointConfig
}

// Compile-time assertion: *Limiter satisfies techniques.RateLimiter.
var _ techniques.RateLimiter = (*Limiter)(nil)

// NewLimiter builds a Limiter. overrides is consulted before the default
// when a new bucket is created for a key. A nil or empty map is fine.
func NewLimiter(overrides map[string]EndpointConfig) *Limiter {
	cp := make(map[string]EndpointConfig, len(overrides))
	for k, v := range overrides {
		cp[k] = v
	}
	return &Limiter{
		buckets:   make(map[string]*rate.Limiter),
		overrides: cp,
		defaultC:  EndpointConfig{RPS: DefaultRPS, Burst: DefaultBurst},
	}
}

// bucket returns the rate.Limiter for key, creating one on first use under
// l.mu. The caller must NOT hold l.mu.
func (l *Limiter) bucket(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[key]; ok {
		return b
	}
	cfg, ok := l.overrides[key]
	if !ok {
		cfg = l.defaultC
	}
	b := rate.NewLimiter(rate.Limit(cfg.RPS), cfg.Burst)
	l.buckets[key] = b
	return b
}

// Wait blocks until a call keyed by key is permitted or ctx is done. A
// cancelled context returns a wrapped error so callers can use errors.Is to
// detect context.Canceled or context.DeadlineExceeded. The underlying
// rate-limiter package occasionally returns its own sentinel when it can
// prove the wait would exceed the deadline; we normalize that to the
// context's own error so callers see one canonical error chain.
func (l *Limiter) Wait(ctx context.Context, key string) error {
	if err := l.bucket(key).Wait(ctx); err != nil {
		// Prefer the context's own error when it has fired, so callers can
		// use errors.Is(err, context.Canceled / context.DeadlineExceeded).
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("ratelimit: wait on %q: %w", key, ctxErr)
		}
		// x/time/rate returns an unexported sentinel of the form
		// "rate: Wait(n=%d) would exceed context deadline" when it can prove
		// the wait would outlast the deadline before it has actually fired.
		// Normalize that to context.DeadlineExceeded so the error chain is
		// stable across rate-package versions.
		if strings.Contains(err.Error(), "would exceed context deadline") {
			return fmt.Errorf("ratelimit: wait on %q: %w", key, context.DeadlineExceeded)
		}
		return fmt.Errorf("ratelimit: wait on %q: %w", key, err)
	}
	return nil
}

// Allow reports whether a call keyed by key is permitted right now without
// blocking. It consumes a token on success.
func (l *Limiter) Allow(key string) bool {
	return l.bucket(key).Allow()
}

// Budget tracks remaining paid-API calls for one invocation. Methods are
// safe for concurrent use; N goroutines charging a budget of M will record
// exactly M successful charges, never more.
type Budget struct {
	mu        sync.Mutex
	remaining map[string]int  // service -> calls remaining, when capped
	unlimited map[string]bool // service -> true when cap was 0 (unlimited)
}

// NewBudget builds a Budget from caps. A cap of 0 means unlimited for that
// service. A negative cap is treated as 0 (exhausted immediately) — that
// keeps the invariant "you cannot make a paid call you didn't authorize".
func NewBudget(caps techniques.BudgetCaps) *Budget {
	b := &Budget{
		remaining: make(map[string]int, 3),
		unlimited: make(map[string]bool, 3),
	}
	b.set("censys", caps.Censys)
	b.set("shodan", caps.Shodan)
	b.set("securitytrails", caps.SecurityTrails)
	return b
}

func (b *Budget) set(service string, limit int) {
	if limit == 0 {
		b.unlimited[service] = true
		return
	}
	if limit < 0 {
		limit = 0
	}
	b.remaining[service] = limit
}

// Charge attempts to consume one call against the named budget. It returns
// false when the budget is exhausted; the caller is then expected to stop
// and surface a "budget_exhausted" TechniqueErr. Unknown services are
// treated as unlimited so adding a new paid technique later does not
// require touching every existing caller.
func (b *Budget) Charge(service string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unlimited[service] {
		return true
	}
	r, tracked := b.remaining[service]
	if !tracked {
		return true
	}
	if r <= 0 {
		return false
	}
	b.remaining[service] = r - 1
	return true
}

// Remaining reports calls left for a service. -1 means unlimited; a tracked
// service returns its remaining count, never going below zero. Unknown
// services also return -1.
func (b *Budget) Remaining(service string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unlimited[service] {
		return -1
	}
	r, tracked := b.remaining[service]
	if !tracked {
		return -1
	}
	return r
}

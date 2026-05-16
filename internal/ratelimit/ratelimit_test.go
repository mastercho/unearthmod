package ratelimit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unearth-tool/unearth/pkg/techniques"
)

func TestLimiter_AllowConsumesBudgetThenRejects(t *testing.T) {
	l := NewLimiter(map[string]EndpointConfig{
		"slow": {RPS: 0.01, Burst: 2}, // 2 tokens, refilling ~once per 100s
	})
	// Two should succeed immediately.
	if !l.Allow("slow") {
		t.Fatal("first Allow should succeed")
	}
	if !l.Allow("slow") {
		t.Fatal("second Allow should succeed")
	}
	// Third must fail — no tokens left, refill is glacial.
	if l.Allow("slow") {
		t.Fatal("third Allow should be denied — bucket empty")
	}
}

func TestLimiter_DefaultRateForUnknownKey(t *testing.T) {
	l := NewLimiter(nil)
	// DefaultBurst=5 by default.
	for i := 0; i < DefaultBurst; i++ {
		if !l.Allow("unconfigured") {
			t.Fatalf("Allow %d should succeed at default burst", i)
		}
	}
	// One more is allowed to be true or false depending on timing slack; the
	// guarantee is only that the *burst* succeeds.
}

func TestLimiter_WaitHonorsContext(t *testing.T) {
	l := NewLimiter(map[string]EndpointConfig{
		"slow": {RPS: 0.01, Burst: 1},
	})
	// Drain the single token.
	if !l.Allow("slow") {
		t.Fatal("seeding Allow should succeed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := l.Wait(ctx, "slow")
	if err == nil {
		t.Fatal("expected context-cancelled error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error chain should include DeadlineExceeded, got %v", err)
	}
}

func TestLimiter_WaitSucceedsForFastBucket(t *testing.T) {
	l := NewLimiter(map[string]EndpointConfig{
		"fast": {RPS: 1000, Burst: 100},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := l.Wait(ctx, "fast"); err != nil {
		t.Fatalf("Wait on fast bucket: %v", err)
	}
}

func TestLimiter_BucketReuseConcurrent(t *testing.T) {
	l := NewLimiter(nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Allow("shared")
		}()
	}
	wg.Wait()
	// Without a mutex around bucket creation we'd race here; -race catches it.
}

func TestBudget_ChargeUntilExhausted(t *testing.T) {
	b := NewBudget(techniques.BudgetCaps{Censys: 3, Shodan: 1, SecurityTrails: 0})
	for i := 0; i < 3; i++ {
		if !b.Charge("censys") {
			t.Fatalf("censys charge %d should succeed", i)
		}
	}
	if b.Charge("censys") {
		t.Error("censys 4th charge should fail")
	}
	if !b.Charge("shodan") {
		t.Error("shodan first charge should succeed")
	}
	if b.Charge("shodan") {
		t.Error("shodan second charge should fail")
	}
	// SecurityTrails is unlimited (cap=0).
	for i := 0; i < 100; i++ {
		if !b.Charge("securitytrails") {
			t.Fatalf("unlimited securitytrails should never fail (i=%d)", i)
		}
	}
}

func TestBudget_NegativeCapTreatedAsZero(t *testing.T) {
	b := NewBudget(techniques.BudgetCaps{Censys: -1})
	if b.Charge("censys") {
		t.Error("negative cap should exhaust immediately")
	}
	if r := b.Remaining("censys"); r != 0 {
		t.Errorf("Remaining: want 0, got %d", r)
	}
}

func TestBudget_RemainingReportsUnlimitedAsMinusOne(t *testing.T) {
	b := NewBudget(techniques.BudgetCaps{Censys: 0})
	if r := b.Remaining("censys"); r != -1 {
		t.Errorf("unlimited Remaining: want -1, got %d", r)
	}
}

func TestBudget_RemainingForUnknownServiceIsUnlimited(t *testing.T) {
	b := NewBudget(techniques.BudgetCaps{})
	if r := b.Remaining("unknown-service"); r != -1 {
		t.Errorf("unknown service: want -1, got %d", r)
	}
	if !b.Charge("unknown-service") {
		t.Error("unknown service should be unlimited")
	}
}

func TestBudget_ConcurrentChargesExactlyN(t *testing.T) {
	// N goroutines hammering a budget of M must result in exactly M
	// successful charges, no more.
	const cap = 100
	const workers = 64
	const opsPerWorker = 10

	b := NewBudget(techniques.BudgetCaps{Shodan: cap})

	var ok int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				if b.Charge("shodan") {
					atomic.AddInt64(&ok, 1)
				}
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&ok); got != cap {
		t.Errorf("successful charges: want exactly %d, got %d", cap, got)
	}
	if r := b.Remaining("shodan"); r != 0 {
		t.Errorf("Remaining after exhaustion: want 0, got %d", r)
	}
}

func TestLimiter_OverrideCopyIsolation(t *testing.T) {
	// Mutating the map passed to NewLimiter after construction must not
	// affect the limiter — protects against accidental aliasing.
	cfg := map[string]EndpointConfig{"x": {RPS: 0.01, Burst: 1}}
	l := NewLimiter(cfg)
	cfg["x"] = EndpointConfig{RPS: 1000, Burst: 1000}
	if !l.Allow("x") {
		t.Fatal("first should succeed")
	}
	if l.Allow("x") {
		t.Fatal("second should fail — original slow config must still apply")
	}
}

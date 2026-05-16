package techniques

import (
	"context"
	"testing"
)

// fakeTechnique is a minimal Technique used to exercise the registry.
type fakeTechnique struct {
	name string
	tier Tier
}

func (f fakeTechnique) Name() string           { return f.name }
func (f fakeTechnique) Tier() Tier             { return f.tier }
func (f fakeTechnique) RequiresAPIKey() bool   { return false }
func (f fakeTechnique) DefaultWeight() float64 { return 0.5 }

func (f fakeTechnique) Run(context.Context, string, RunOptions) ([]Candidate, error) {
	return nil, nil
}

// withCleanRegistry swaps in an empty registry for the duration of a test and
// restores the original afterwards, keeping tests isolated from one another.
func withCleanRegistry(t *testing.T) {
	t.Helper()
	saved := registry
	registry = map[string]Technique{}
	t.Cleanup(func() { registry = saved })
}

func TestRegisterAndGet(t *testing.T) {
	withCleanRegistry(t)

	Register(fakeTechnique{name: "alpha", tier: TierPassive})

	got, ok := Get("alpha")
	if !ok {
		t.Fatal("Get(alpha) not found after Register")
	}
	if got.Name() != "alpha" {
		t.Fatalf("Get(alpha).Name() = %q, want alpha", got.Name())
	}
	if _, ok := Get("missing"); ok {
		t.Fatal("Get(missing) reported found")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	withCleanRegistry(t)

	Register(fakeTechnique{name: "dup", tier: TierPassive})

	defer func() {
		if recover() == nil {
			t.Fatal("duplicate Register did not panic")
		}
	}()
	Register(fakeTechnique{name: "dup", tier: TierActive})
}

func TestAllSorted(t *testing.T) {
	withCleanRegistry(t)

	Register(fakeTechnique{name: "charlie", tier: TierPassive})
	Register(fakeTechnique{name: "alpha", tier: TierPassive})
	Register(fakeTechnique{name: "bravo", tier: TierPassive})

	all := All()
	want := []string{"alpha", "bravo", "charlie"}
	if len(all) != len(want) {
		t.Fatalf("All() len = %d, want %d", len(all), len(want))
	}
	for i, w := range want {
		if all[i].Name() != w {
			t.Fatalf("All()[%d] = %q, want %q", i, all[i].Name(), w)
		}
	}
}

func TestByTier(t *testing.T) {
	withCleanRegistry(t)

	Register(fakeTechnique{name: "p", tier: TierPassive})
	Register(fakeTechnique{name: "a", tier: TierActive})
	Register(fakeTechnique{name: "g", tier: TierAggressive})

	if got := len(ByTier(TierPassive)); got != 1 {
		t.Fatalf("ByTier(passive) len = %d, want 1", got)
	}
	if got := len(ByTier(TierActive)); got != 2 {
		t.Fatalf("ByTier(active) len = %d, want 2", got)
	}
	if got := len(ByTier(TierAggressive)); got != 3 {
		t.Fatalf("ByTier(aggressive) len = %d, want 3", got)
	}
}

func TestTierString(t *testing.T) {
	cases := map[Tier]string{
		TierPassive:    "passive",
		TierActive:     "active",
		TierAggressive: "aggressive",
		Tier(99):       "unknown",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Fatalf("Tier(%d).String() = %q, want %q", int(tier), got, want)
		}
	}
}

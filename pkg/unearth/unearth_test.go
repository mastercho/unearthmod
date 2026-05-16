package unearth

import (
	"context"
	"testing"

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

func TestDiscoverStub(t *testing.T) {
	res, err := Discover(context.Background(), "example.com", DefaultOptions())
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if res == nil {
		t.Fatal("Discover returned nil result")
	}
	if res.Target != "example.com" {
		t.Errorf("Result.Target = %q, want example.com", res.Target)
	}
	if res.Timestamp.IsZero() {
		t.Error("Result.Timestamp not set")
	}
}

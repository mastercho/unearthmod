package techniques

import (
	"context"
	"strings"
	"testing"
)

func TestIPv6Probe_FindsNonCDNAAAA(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		// origin-style subdomain has a v6 record; the bare target has a v4 only.
		"origin.example.test": {"2001:db8::1"},
		"example.test":        {"203.0.113.5"},
	}
	withFakeResolver(t, fr)
	out, err := ipv6ProbeTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "2001:db8::1" {
		t.Fatalf("want one v6 candidate, got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "ipv6_probe") {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
}

func TestIPv6Probe_FiltersV4(t *testing.T) {
	// All A records are v4 — technique should yield nothing.
	fr := newFakeResolver()
	fr.A = map[string][]string{"example.test": {"203.0.113.5"}}
	withFakeResolver(t, fr)
	out, _ := ipv6ProbeTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 0 {
		t.Errorf("v4-only should produce zero v6 candidates, got %+v", out)
	}
}

func TestIPv6Probe_FiltersCDNRanges(t *testing.T) {
	// Cloudflare v6 prefix 2606:4700::/32 — should be filtered out.
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"example.test": {"2606:4700::1234"},
	}
	withFakeResolver(t, fr)
	out, _ := ipv6ProbeTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 0 {
		t.Errorf("Cloudflare v6 should be filtered, got %+v", out)
	}
}

func TestIPv6ProbeTechnique_Metadata(t *testing.T) {
	p := ipv6ProbeTechnique{}
	if p.Name() != "ipv6_probe" || p.Tier() != TierAggressive || p.RequiresAPIKey() || p.DefaultWeight() != 0.70 {
		t.Errorf("metadata wrong: %+v", p)
	}
}

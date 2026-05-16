package techniques

import (
	"context"
	"strings"
	"testing"
)

func TestSubdomain_Run_FindsResolvedOrigins(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"origin.example.test":  {"203.0.113.7"},
		"direct.example.test":  {"203.0.113.8"},
		"webmail.example.test": {"203.0.113.9"},
		// Cloudflare IP that must be filtered.
		"dev.example.test": {"104.16.0.5"},
	}
	withFakeResolver(t, fr)

	out, err := subdomainTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ips := map[string]bool{}
	for _, c := range out {
		ips[c.IP] = true
		if !strings.Contains(c.Evidence, "subdomain") {
			t.Errorf("evidence missing subdomain mention: %q", c.Evidence)
		}
	}
	for _, want := range []string{"203.0.113.7", "203.0.113.8", "203.0.113.9"} {
		if !ips[want] {
			t.Errorf("missing %s in %v", want, ips)
		}
	}
	if ips["104.16.0.5"] {
		t.Error("Cloudflare IP should be filtered out")
	}
}

func TestSubdomain_Run_EmptyDNSResults(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	out, err := subdomainTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("no DNS hits → no candidates, got %+v", out)
	}
}

func TestSubdomain_WordlistNonEmpty(t *testing.T) {
	if got := len(subdomainPrefixes()); got < 20 {
		t.Errorf("wordlist seems too small: %d entries", got)
	}
}

func TestSubdomainTechnique_Metadata(t *testing.T) {
	s := subdomainTechnique{}
	if s.Name() != "subdomain_enum" || s.Tier() != TierPassive || s.RequiresAPIKey() || s.DefaultWeight() != 0.35 {
		t.Errorf("metadata wrong: %+v", s)
	}
}

func TestSubdomain_Run_ContextCancelled(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Should return promptly even when ctx is already done.
	_, _ = subdomainTechnique{}.Run(ctx, "example.test", RunOptions{})
}

package techniques

import (
	"context"
	"strings"
	"testing"
)

func TestSPFMX_Run_AllMechanisms(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test":      {"v=spf1 ip4:203.0.113.10 ip6:2001:db8::1 a:relay.example.test mx include:_spf.example.test ~all"},
		"_spf.example.test": {"v=spf1 ip4:198.51.100.50 ~all"},
	}
	fr.A = map[string][]string{
		"relay.example.test": {"203.0.113.20"},
		"mail.example.test":  {"203.0.113.30"},
	}
	fr.MX = map[string][]string{
		"example.test": {"mail.example.test"},
	}
	withFakeResolver(t, fr)

	out, err := spfMXTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ips := map[string]bool{}
	for _, c := range out {
		ips[c.IP] = true
	}
	for _, want := range []string{
		"203.0.113.10",  // ip4:
		"2001:db8::1",   // ip6:
		"203.0.113.20",  // a: relay
		"203.0.113.30",  // mx and mx target
		"198.51.100.50", // include: one level
	} {
		if !ips[want] {
			t.Errorf("missing IP %s in %v", want, ips)
		}
	}
}

func TestSPFMX_Run_UsesApexAndAcceptsQualifiedMechanisms(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"gaytell.com": {"v=spf1 +ip4:104.223.9.26 +a +mx +ip4:104.223.9.141 ~all"},
	}
	fr.A = map[string][]string{
		"gaytell.com":      {"104.223.9.26"},
		"mail.gaytell.com": {"104.223.9.199"},
	}
	fr.MX = map[string][]string{
		"gaytell.com": {"mail.gaytell.com"},
	}
	withFakeResolver(t, fr)

	out, err := spfMXTechnique{}.Run(context.Background(), "www.gaytell.com", RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ips := map[string]bool{}
	for _, c := range out {
		ips[c.IP] = true
	}
	for _, want := range []string{"104.223.9.26", "104.223.9.141", "104.223.9.199"} {
		if !ips[want] {
			t.Errorf("missing qualified apex SPF/MX IP %s in %+v", want, out)
		}
	}
}

func TestSPFLookupHosts(t *testing.T) {
	tests := []struct {
		target string
		want   []string
	}{
		{target: "www.example.com", want: []string{"example.com", "www.example.com"}},
		{target: "https://shop.example.co.uk:443/path", want: []string{"example.co.uk", "shop.example.co.uk"}},
		{target: "example.test", want: []string{"example.test"}},
	}
	for _, tt := range tests {
		got := spfLookupHosts(tt.target)
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("spfLookupHosts(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestSPFMX_Run_IgnoresNonSPFTXT(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test": {"google-site-verification=abc", "random=value"},
	}
	withFakeResolver(t, fr)
	out, _ := spfMXTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 0 {
		t.Errorf("non-SPF TXT should produce no candidates, got %+v", out)
	}
}

func TestSPFMX_Run_IncludesAreOneLevelDeep(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test": {"v=spf1 include:level1.test ~all"},
		"level1.test":  {"v=spf1 ip4:203.0.113.50 include:level2.test ~all"},
		"level2.test":  {"v=spf1 ip4:203.0.113.99 ~all"},
	}
	withFakeResolver(t, fr)
	out, _ := spfMXTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	hasLevel1 := false
	hasLevel2 := false
	for _, c := range out {
		if c.IP == "203.0.113.50" {
			hasLevel1 = true
		}
		if c.IP == "203.0.113.99" {
			hasLevel2 = true
		}
	}
	if !hasLevel1 {
		t.Error("level-1 include should be expanded")
	}
	if hasLevel2 {
		t.Error("level-2 include should NOT be expanded (one level deep)")
	}
}

func TestSPFMX_Run_FiltersCDN(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test": {"v=spf1 ip4:104.16.0.5 ip4:203.0.113.7 ~all"},
	}
	withFakeResolver(t, fr)
	out, _ := spfMXTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	for _, c := range out {
		if c.IP == "104.16.0.5" {
			t.Errorf("Cloudflare IP should be filtered: %v", c)
		}
	}
	if len(out) != 1 || out[0].IP != "203.0.113.7" {
		t.Errorf("want one non-CDN IP, got %v", out)
	}
}

func TestSPFMX_Run_Evidence(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{"example.test": {"v=spf1 ip4:203.0.113.10 ~all"}}
	withFakeResolver(t, fr)
	out, _ := spfMXTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(out))
	}
	if !strings.Contains(out[0].Evidence, "SPF ip4") || !strings.Contains(out[0].Evidence, "example.test") {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
}

func TestSPFMXTechnique_Metadata(t *testing.T) {
	s := spfMXTechnique{}
	if s.Name() != "spf_mx" || s.Tier() != TierPassive || s.RequiresAPIKey() || s.DefaultWeight() != 0.50 {
		t.Errorf("metadata wrong: %+v", s)
	}
}

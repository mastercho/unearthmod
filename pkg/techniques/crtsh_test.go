package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const crtshSampleJSON = `[
  {"common_name":"www.example.test","name_value":"www.example.test\nexample.test"},
  {"common_name":"*.example.test","name_value":"origin.example.test"},
  {"common_name":"other-zone.com","name_value":"other-zone.com"}
]`

func TestCrtsh_Run_Happy(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"www.example.test":    {"203.0.113.5"},
		"example.test":        {"203.0.113.5"},
		"origin.example.test": {"203.0.113.7"},
	}
	withFakeResolver(t, fr)

	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(_ *http.Request) (*http.Response, error) {
			return stubResponse(200, crtshSampleJSON), nil
		},
	})

	out, err := crtshTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 unique IPs, got %d: %+v", len(out), out)
	}
	ips := map[string]bool{}
	for _, c := range out {
		ips[c.IP] = true
		if !strings.Contains(c.Evidence, "crt.sh") {
			t.Errorf("evidence missing source attribution: %q", c.Evidence)
		}
	}
	if !ips["203.0.113.5"] || !ips["203.0.113.7"] {
		t.Errorf("missing expected IPs: %v", ips)
	}
}

func TestCrtsh_Run_EmptyResult(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `[]`), nil
		},
	})
	out, err := crtshTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty crt.sh response should yield no candidates, got %v", out)
	}
}

func TestCrtsh_Run_MalformedJSON(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{not-json`), nil
		},
	})
	_, err := crtshTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err == nil {
		t.Fatal("malformed JSON should produce an error")
	}
}

func TestCrtsh_Run_HTTPError(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ``), nil
		},
	})
	_, err := crtshTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err == nil {
		t.Fatal("5xx should produce an error")
	}
}

func TestCrtsh_Run_FiltersCloudflareIP(t *testing.T) {
	fr := newFakeResolver()
	// Cloudflare-range IP (104.16.0.0/13) — must be dropped.
	fr.A = map[string][]string{
		"www.example.test": {"104.16.0.5"},
	}
	withFakeResolver(t, fr)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `[{"common_name":"www.example.test","name_value":"www.example.test"}]`), nil
		},
	})
	out, err := crtshTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("Cloudflare IP should be filtered out, got %v", out)
	}
}

func TestCrtsh_Run_ContextCancelled(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := crtshTechnique{}.Run(ctx, "example.test", RunOptions{HTTPClient: hc})
	if err == nil {
		t.Fatal("expected context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in chain, got %v", err)
	}
}

func TestCrtshTechnique_Metadata(t *testing.T) {
	c := crtshTechnique{}
	if c.Name() != "crtsh" {
		t.Errorf("Name = %q", c.Name())
	}
	if c.Tier() != TierPassive {
		t.Errorf("Tier = %v", c.Tier())
	}
	if c.RequiresAPIKey() {
		t.Error("crtsh should not require API key")
	}
	if c.DefaultWeight() != 0.55 {
		t.Errorf("DefaultWeight = %g", c.DefaultWeight())
	}
}

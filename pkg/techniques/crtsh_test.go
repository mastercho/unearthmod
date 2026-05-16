package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	withCrtshFastRetry(t)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ``), nil
		},
		"https://api.certspotter.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ``), nil // fallback also down
		},
	})
	_, err := crtshTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err == nil {
		t.Fatal("5xx after retries + failing fallback should produce an error")
	}
}

// withCrtshFastRetry shrinks the crtsh retry sleep so retry-path tests
// run in milliseconds rather than seconds.
func withCrtshFastRetry(t *testing.T) {
	t.Helper()
	prev := crtshInitialDelay
	crtshInitialDelay = 5 * time.Millisecond
	t.Cleanup(func() { crtshInitialDelay = prev })
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

func TestCrtsh_Run_RetrySucceedsOnAttempt3(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	withCrtshFastRetry(t)
	var attempts atomic.Int32
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(*http.Request) (*http.Response, error) {
			n := attempts.Add(1)
			if n < 3 {
				return stubResponse(500, ``), nil
			}
			return stubResponse(200, `[]`), nil
		},
	})
	_, err := crtshTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("retry should succeed on attempt 3: %v", err)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestCrtsh_Run_FallbackOnPersistentFailure(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{"origin.example.test": {"203.0.113.42"}}
	withFakeResolver(t, fr)
	withCrtshFastRetry(t)
	var crtshAttempts, fallbackAttempts atomic.Int32
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(*http.Request) (*http.Response, error) {
			crtshAttempts.Add(1)
			return stubResponse(500, ``), nil
		},
		"https://api.certspotter.com/": func(*http.Request) (*http.Response, error) {
			fallbackAttempts.Add(1)
			return stubResponse(200,
				`[{"cert_sha256":"abc","dns_names":["origin.example.test"]}]`), nil
		},
	})
	out, err := crtshTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("fallback should succeed: %v", err)
	}
	if crtshAttempts.Load() != crtshMaxAttempts {
		t.Errorf("expected %d crt.sh attempts, got %d", crtshMaxAttempts, crtshAttempts.Load())
	}
	if fallbackAttempts.Load() != 1 {
		t.Errorf("expected 1 fallback attempt, got %d", fallbackAttempts.Load())
	}
	if len(out) != 1 || out[0].IP != "203.0.113.42" {
		t.Fatalf("expected one candidate from fallback, got %+v", out)
	}
}

func TestCrtsh_Run_RetryStopsOnContextCancel(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	withCrtshFastRetry(t)
	var attempts atomic.Int32
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://crt.sh/": func(req *http.Request) (*http.Response, error) {
			attempts.Add(1)
			// Block until context cancels, then return that error.
			<-req.Context().Done()
			return nil, req.Context().Err()
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := crtshTechnique{}.Run(ctx, "example.test", RunOptions{HTTPClient: hc})
	if err == nil {
		t.Fatal("expected context error")
	}
	if attempts.Load() > 1 {
		t.Errorf("retry should NOT continue after ctx cancel, attempts=%d", attempts.Load())
	}
}

func TestCrtsh_TimeoutOverride(t *testing.T) {
	c := crtshTechnique{}
	if got := c.TimeoutOverride(); got != 90*time.Second {
		t.Errorf("TimeoutOverride = %v, want 90s", got)
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

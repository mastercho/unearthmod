package techniques

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestErrorPage_ExtractsEmbeddedIP(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/": func(req *http.Request) (*http.Response, error) {
			// Different probes return different responses; one carries an
			// origin IP in the body.
			if req.Host == "definitely-not-here.invalid" {
				return stubResponse(404,
					"<html><body><h1>404 — host not configured</h1>\n"+
						"<p>upstream: 203.0.113.42</p></body></html>"), nil
			}
			return stubResponse(403, "blocked"), nil
		},
	})
	out, err := errorPageTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "203.0.113.42" {
		t.Fatalf("want one extracted IP (.42), got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "unknown-vhost") {
		t.Errorf("evidence should name the probe: %q", out[0].Evidence)
	}
}

func TestErrorPage_FiltersUnroutableAndCDN(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/": func(*http.Request) (*http.Response, error) {
			// Body mentions a few IPs: RFC1918, loopback, Cloudflare, real.
			return stubResponse(500, "stack trace: 10.0.0.1 / 127.0.0.1 / 104.16.0.5 / 198.51.100.7"), nil
		},
	})
	out, _ := errorPageTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if len(out) != 1 || out[0].IP != "198.51.100.7" {
		t.Fatalf("want only 198.51.100.7, got %+v", out)
	}
}

func TestErrorPage_NoIPsInBodyYieldsNoCandidates(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, "<html>boring content</html>"), nil
		},
	})
	out, _ := errorPageTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %+v", out)
	}
}

func TestErrorPage_ContextCancellation(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/": func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := errorPageTechnique{}.Run(ctx, "example.test", RunOptions{HTTPClient: hc})
	if err == nil {
		t.Fatal("expected ctx error")
	}
}

func TestErrorPageTechnique_Metadata(t *testing.T) {
	e := errorPageTechnique{}
	if e.Name() != "error_page" || e.Tier() != TierAggressive || e.RequiresAPIKey() || e.DefaultWeight() != 0.60 {
		t.Errorf("metadata wrong: %+v", e)
	}
}

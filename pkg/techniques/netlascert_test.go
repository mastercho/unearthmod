package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// netlasPage is a responses-search payload. 104.16.0.5 is a Cloudflare edge
// IP and must be filtered. 203.0.113.50 appears twice to exercise dedup.
const netlasPage = `{
  "items": [
    {"data": {"ip": "203.0.113.50"}},
    {"data": {"ip": "104.16.0.5"}},
    {"data": {"ip": "203.0.113.51"}},
    {"data": {"ip": "203.0.113.50"}}
  ]
}`

func netlasKeys() APIKeys { return APIKeys{NetlasAPIKey: "netlas-tok"} }

func TestNetlas_MissingKey(t *testing.T) {
	if _, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestNetlas_Happy(t *testing.T) {
	withStubFingerprint(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "Bearer netlas-tok" {
				t.Errorf("Authorization header: got %q", req.Header.Get("Authorization"))
			}
			q := req.URL.Query()
			qv := q.Get("q")
			if !strings.Contains(qv, "certificate.fingerprint_sha256") {
				t.Errorf("query missing cert field: %q", qv)
			}
			if !strings.Contains(qv, "deadbeef") {
				t.Errorf("query missing fingerprint: %q", qv)
			}
			if got := q.Get("fields"); got != "ip" {
				t.Errorf("fields = %q, want ip", got)
			}
			if got := q.Get("source_type"); got != "include" {
				t.Errorf("source_type = %q, want include", got)
			}
			if got := q.Get("start"); got != "0" {
				t.Errorf("start = %q, want 0", got)
			}
			if q.Has("size") {
				t.Errorf("GET responses search should not send unsupported size parameter")
			}
			return stubResponse(200, netlasPage), nil
		},
	})
	out, err := (netlasCertTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN deduped IPs (cloudflare filtered), got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "Netlas") || !strings.Contains(c.Evidence, "sha256:") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] {
		t.Errorf("expected both 203.0.113.50 and 203.0.113.51, got %v", gotIPs)
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestNetlas_EmptyResult(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"items":[]}`), nil
		},
	})
	out, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %v", out)
	}
}

func TestNetlas_401_IsMissingKey(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestNetlas_403_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestNetlas_429_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (daily allowance) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestNetlas_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"Daily request limit exceeded, please upgrade your subscription"}`), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestNetlas_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"Invalid API key"}`), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-key envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestNetlas_GenericError(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"something unexpected"}`), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestNetlas_5xx_IsHardError(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestNetlas_400IncludesProviderBody(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(400, `{"detail":"Invalid query"}`), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if err == nil || !strings.Contains(err.Error(), "Invalid query") {
		t.Fatalf("400 should include provider body, got %v", err)
	}
}

func TestNetlas_400APIKeyNotFound_IsMissingKey(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(400, `{"detail":"Request had invalid authorization credentials: API key not found"}`), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("400 API key rejection should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestNetlas_MalformedJSON(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://app.netlas.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestNetlas_FingerprintError(t *testing.T) {
	withStubFingerprint(t, "", errors.New("dial failed"))
	hc, _ := stubClient(nil)
	_, err := (netlasCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    netlasKeys(),
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want fingerprint error, got %v", err)
	}
}

func TestNetlasTechnique_Metadata(t *testing.T) {
	n := netlasCertTechnique{}
	if n.Name() != "netlas_cert" || n.Tier() != TierPassive || !n.RequiresAPIKey() || n.DefaultWeight() != 0.75 {
		t.Errorf("metadata wrong: %+v", n)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "x", "y"); got != "x" {
		t.Errorf("firstNonEmpty: got %q want x", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("firstNonEmpty all empty: got %q want empty", got)
	}
}

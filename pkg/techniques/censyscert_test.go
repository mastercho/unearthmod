package techniques

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Platform search-response shape, with nested host.ip per the v3 schema.
const censysPlatformPage1 = `{
  "result": {
    "hits": [
      {"host":{"ip":"203.0.113.50"}},
      {"host":{"ip":"104.16.0.5"}},
      {"host":{"ip":"203.0.113.51"}}
    ],
    "next_page_token": ""
  }
}`

const censysPlatformPage1WithMore = `{
  "result": {
    "hits": [{"host":{"ip":"203.0.113.50"}}],
    "next_page_token": "page-2-token"
  }
}`

const censysPlatformPage2 = `{
  "result": {
    "hits": [{"host":{"ip":"203.0.113.99"}}],
    "next_page_token": ""
  }
}`

func withStubFingerprint(t *testing.T, fp string, err error) {
	t.Helper()
	prev := tlsFingerprint
	tlsFingerprint = func(context.Context, string) (string, error) { return fp, err }
	t.Cleanup(func() { tlsFingerprint = prev })
}

func TestCensys_MissingPAT(t *testing.T) {
	_, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
	// Empty PAT alone is still ErrMissingAPIKey — covers the "only legacy
	// creds were set" scenario (legacy creds are intentionally not
	// referenced here so this test does not depend on deprecated fields).
	_, err = censysCertTechnique{}.Run(context.Background(), "x",
		RunOptions{APIKeys: APIKeys{CensysPlatformPAT: ""}})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("empty PAT should be ErrMissingAPIKey, got %v", err)
	}
}

func TestCensys_Happy(t *testing.T) {
	withStubFingerprint(t, "deadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("Authorization"); got != "Bearer pat-token" {
				t.Errorf("Authorization header: got %q want %q", got, "Bearer pat-token")
			}
			if got := req.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type: got %q", got)
			}
			body, _ := io.ReadAll(req.Body)
			var parsed censysSearchRequest
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Fatalf("body not valid JSON: %v", err)
			}
			if !strings.Contains(parsed.Query, "deadbeef") {
				t.Errorf("query missing fingerprint: %q", parsed.Query)
			}
			if !strings.Contains(parsed.Query, censysFingerprintField) {
				t.Errorf("query missing CenQL field: %q", parsed.Query)
			}
			return stubResponse(200, censysPlatformPage1), nil
		},
	})
	out, err := censysCertTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN IPs, got %d: %+v", len(out), out)
	}
	for _, c := range out {
		if !strings.Contains(c.Evidence, "Censys") || !strings.Contains(c.Evidence, "deadbeef") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d (%v)", len(rt.calls), rt.calls)
	}
}

func TestCensys_Pagination(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	pageNum := 0
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(req *http.Request) (*http.Response, error) {
			pageNum++
			body, _ := io.ReadAll(req.Body)
			var parsed censysSearchRequest
			_ = json.Unmarshal(body, &parsed)
			switch pageNum {
			case 1:
				if parsed.PageToken != "" {
					t.Errorf("page 1 should have empty token, got %q", parsed.PageToken)
				}
				return stubResponse(200, censysPlatformPage1WithMore), nil
			case 2:
				if parsed.PageToken != "page-2-token" {
					t.Errorf("page 2 token: got %q", parsed.PageToken)
				}
				return stubResponse(200, censysPlatformPage2), nil
			default:
				t.Errorf("unexpected extra page request %d", pageNum)
				return stubResponse(500, ""), nil
			}
		},
	})
	out, err := censysCertTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pageNum != 2 {
		t.Errorf("expected 2 page requests, saw %d", pageNum)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 candidates across pages, got %d: %+v", len(out), out)
	}
}

func TestCensys_EmptyResult(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"result":{"hits":[],"next_page_token":""}}`), nil
		},
	})
	out, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty Censys hits should produce no candidates, got %v", out)
	}
}

func TestCensys_BudgetExhausted(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(nil)
	_, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat"},
		Budget:     exhaustedBudget{},
	})
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("want ErrBudgetExhausted, got %v", err)
	}
}

type exhaustedBudget struct{}

func (exhaustedBudget) Charge(string) bool   { return false }
func (exhaustedBudget) Remaining(string) int { return 0 }

func TestCensys_FingerprintError(t *testing.T) {
	withStubFingerprint(t, "", errors.New("tls dial failed"))
	hc, _ := stubClient(nil)
	_, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat"},
	})
	if err == nil {
		t.Fatal("expected error when fingerprint cannot be obtained")
	}
}

func TestCensys_HTTPError(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ``), nil
		},
	})
	_, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat"},
	})
	if err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestCensys_MalformedJSON(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat"},
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestCensysCertTechnique_Metadata(t *testing.T) {
	c := censysCertTechnique{}
	if c.Name() != "censys_cert" || c.Tier() != TierPassive || !c.RequiresAPIKey() || c.DefaultWeight() != 0.90 {
		t.Errorf("metadata wrong: %+v", c)
	}
}

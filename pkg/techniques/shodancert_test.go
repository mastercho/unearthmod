package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const shodanPage1 = `{
  "matches": [
    {"ip_str":"203.0.113.50"},
    {"ip_str":"104.16.0.5"},
    {"ip_str":"203.0.113.51"}
  ],
  "total": 3
}`

const shodanPage1WithMore = `{"matches":[{"ip_str":"203.0.113.50"}],"total":2}`
const shodanPage2 = `{"matches":[{"ip_str":"203.0.113.99"}],"total":2}`

func withStubFingerprintSHA1(t *testing.T, fp string, err error) {
	t.Helper()
	prev := tlsFingerprintSHA1
	tlsFingerprintSHA1 = func(context.Context, string) (string, error) { return fp, err }
	t.Cleanup(func() { tlsFingerprintSHA1 = prev })
}

func TestShodan_MissingKey(t *testing.T) {
	_, err := shodanCertTechnique{}.Run(context.Background(), "x", RunOptions{})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
}

func TestShodan_Happy(t *testing.T) {
	withStubFingerprintSHA1(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(req *http.Request) (*http.Response, error) {
			q := req.URL.Query()
			if q.Get("key") != "shodan-tok" {
				t.Errorf("key param: got %q", q.Get("key"))
			}
			if !strings.Contains(q.Get("query"), "ssl.cert.fingerprint:") {
				t.Errorf("query missing filter: %q", q.Get("query"))
			}
			if !strings.Contains(q.Get("query"), "deadbeef") {
				t.Errorf("query missing fingerprint: %q", q.Get("query"))
			}
			return stubResponse(200, shodanPage1), nil
		},
	})
	out, err := shodanCertTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "shodan-tok"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN IPs, got %d: %+v", len(out), out)
	}
	for _, c := range out {
		if !strings.Contains(c.Evidence, "Shodan") || !strings.Contains(c.Evidence, "sha1:") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestShodan_Pagination(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	pageNum := 0
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(req *http.Request) (*http.Response, error) {
			pageNum++
			q := req.URL.Query()
			switch pageNum {
			case 1:
				if q.Get("page") != "" {
					t.Errorf("page 1 should not set page param, got %q", q.Get("page"))
				}
				return stubResponse(200, shodanPage1WithMore), nil
			case 2:
				if q.Get("page") != "2" {
					t.Errorf("page 2 param: %q", q.Get("page"))
				}
				return stubResponse(200, shodanPage2), nil
			default:
				t.Errorf("unexpected page %d", pageNum)
				return stubResponse(500, ""), nil
			}
		},
	})
	out, err := shodanCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pageNum != 2 {
		t.Errorf("expected 2 page requests, got %d", pageNum)
	}
	if len(out) != 2 {
		t.Errorf("merged candidates: %+v", out)
	}
}

func TestShodan_TierInsufficient_403(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := shodanCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestShodan_TierInsufficient_200WithUpgradeError(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"Access denied (please upgrade your API plan)"}`), nil
		},
	})
	_, err := shodanCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("200+upgrade should produce ErrTierInsufficient, got %v", err)
	}
}

func TestShodan_BadKey_401(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, `{"error":"Invalid API key"}`), nil
		},
	})
	_, err := shodanCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "bogus"},
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestShodan_BudgetExhausted(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(nil)
	_, err := shodanCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		Budget:     exhaustedBudget{},
	})
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("want ErrBudgetExhausted, got %v", err)
	}
}

func TestShodan_EmptyResult(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"matches":[],"total":0}`), nil
		},
	})
	out, err := shodanCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %v", out)
	}
}

func TestShodan_MalformedJSON(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := shodanCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestShodanTechnique_Metadata(t *testing.T) {
	s := shodanCertTechnique{}
	if s.Name() != "shodan_cert" || s.Tier() != TierActive || !s.RequiresAPIKey() || s.DefaultWeight() != 0.85 {
		t.Errorf("metadata wrong: %+v", s)
	}
}

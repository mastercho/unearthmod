package techniques

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const censysSampleJSON = `{
  "result": {
    "hits": [
      {"ip":"203.0.113.50"},
      {"ip":"104.16.0.5"},
      {"ip":"203.0.113.51"}
    ]
  }
}`

func withStubFingerprint(t *testing.T, fp string, err error) {
	t.Helper()
	prev := tlsFingerprint
	tlsFingerprint = func(context.Context, string) (string, error) { return fp, err }
	t.Cleanup(func() { tlsFingerprint = prev })
}

func TestCensys_MissingKey(t *testing.T) {
	_, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
	_, err = censysCertTechnique{}.Run(context.Background(), "x",
		RunOptions{APIKeys: APIKeys{CensysAPIID: "only-id"}})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("partial key should be ErrMissingAPIKey, got %v", err)
	}
}

func TestCensys_Happy(t *testing.T) {
	withStubFingerprint(t, "deadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://search.censys.io/": func(req *http.Request) (*http.Response, error) {
			// Confirm Basic auth header.
			auth := req.Header.Get("Authorization")
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("id:sec"))
			if auth != want {
				t.Errorf("auth header: got %q want %q", auth, want)
			}
			// Confirm fingerprint is in the query.
			if !strings.Contains(req.URL.RawQuery, "deadbeef") {
				t.Errorf("fingerprint missing from query: %s", req.URL.RawQuery)
			}
			return stubResponse(200, censysSampleJSON), nil
		},
	})
	out, err := censysCertTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysAPIID: "id", CensysAPISecret: "sec"},
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

func TestCensys_BudgetExhausted(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(nil)
	_, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysAPIID: "id", CensysAPISecret: "sec"},
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
		APIKeys:    APIKeys{CensysAPIID: "id", CensysAPISecret: "sec"},
	})
	if err == nil {
		t.Fatal("expected error when fingerprint cannot be obtained")
	}
}

func TestCensys_HTTPError(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://search.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ``), nil
		},
	})
	_, err := censysCertTechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysAPIID: "id", CensysAPISecret: "sec"},
	})
	if err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestCensysCertTechnique_Metadata(t *testing.T) {
	c := censysCertTechnique{}
	if c.Name() != "censys_cert" || c.Tier() != TierPassive || !c.RequiresAPIKey() || c.DefaultWeight() != 0.90 {
		t.Errorf("metadata wrong: %+v", c)
	}
}

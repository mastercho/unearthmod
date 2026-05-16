package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const stHistorySample = `{
  "records": [
    {"values":[{"ip":"203.0.113.10"}],"first_seen":"2018-01-01","last_seen":"2019-06-01"},
    {"values":[{"ip":"203.0.113.20"},{"ip":"104.16.0.5"}],"first_seen":"2020-01-01","last_seen":"2021-12-31"}
  ]
}`

const viewdnsSample = `{
  "response": {
    "records": [
      {"ip":"198.51.100.7","lastseen":"2022-03-15"},
      {"ip":"104.16.0.5","lastseen":"2024-01-01"}
    ]
  }
}`

func TestDNSHistory_MissingKey(t *testing.T) {
	_, err := dnsHistoryTechnique{}.Run(context.Background(), "x", RunOptions{})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
}

func TestDNSHistory_SecurityTrails(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.securitytrails.com/": func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("APIKEY"); got != "test-key" {
				t.Errorf("missing APIKEY header (got %q)", got)
			}
			return stubResponse(200, stHistorySample), nil
		},
	})
	out, err := dnsHistoryTechnique{}.Run(
		context.Background(),
		"example.test",
		RunOptions{
			HTTPClient: hc,
			APIKeys:    APIKeys{SecurityTrailsKey: "test-key"},
		},
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 104.16.0.5 is Cloudflare → filtered. Two unique non-CDN IPs remain.
	if len(out) != 2 {
		t.Fatalf("want 2 candidates, got %d: %+v", len(out), out)
	}
	for _, c := range out {
		if !strings.Contains(c.Evidence, "SecurityTrails") {
			t.Errorf("evidence should attribute SecurityTrails: %q", c.Evidence)
		}
	}
}

func TestDNSHistory_ViewDNSFallback(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.viewdns.info/": func(req *http.Request) (*http.Response, error) {
			if !strings.Contains(req.URL.RawQuery, "apikey=vd-key") {
				t.Errorf("ViewDNS apikey not in query: %s", req.URL.RawQuery)
			}
			return stubResponse(200, viewdnsSample), nil
		},
	})
	out, err := dnsHistoryTechnique{}.Run(
		context.Background(),
		"example.test",
		RunOptions{HTTPClient: hc, APIKeys: APIKeys{ViewDNSKey: "vd-key"}},
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "198.51.100.7" {
		t.Fatalf("want one non-CDN IP (.7), got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "ViewDNS") {
		t.Errorf("evidence should attribute ViewDNS: %q", out[0].Evidence)
	}
}

func TestDNSHistory_HTTPError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.securitytrails.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ``), nil
		},
	})
	_, err := dnsHistoryTechnique{}.Run(
		context.Background(), "x",
		RunOptions{HTTPClient: hc, APIKeys: APIKeys{SecurityTrailsKey: "k"}},
	)
	if err == nil {
		t.Fatal("expected error on 403")
	}
}

func TestDNSHistoryTechnique_Metadata(t *testing.T) {
	d := dnsHistoryTechnique{}
	if d.Name() != "dns_history" || d.Tier() != TierPassive || !d.RequiresAPIKey() || d.DefaultWeight() != 0.65 {
		t.Errorf("metadata wrong: %+v", d)
	}
}

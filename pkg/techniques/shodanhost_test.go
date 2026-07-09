package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestShodanHost_Happy(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(req *http.Request) (*http.Response, error) {
			query := req.URL.Query().Get("query")
			switch query {
			case "hostname:www.printerinks.com":
				return stubResponse(200, `{"matches":[{"ip_str":"104.26.10.69"},{"ip":98733307,"hostnames":["www.printerinks.com"],"port":443,"product":"nginx"}],"total":2}`), nil
			case "hostname:printerinks.com":
				return stubResponse(200, `{"matches":[{"ip_str":"5.226.140.251","hostnames":["printerinks.com"],"port":80}],"total":1}`), nil
			default:
				t.Fatalf("unexpected Shodan query %q", query)
				return stubResponse(200, `{"matches":[],"total":0}`), nil
			}
		},
	})

	out, err := shodanHostTechnique{}.Run(context.Background(), "www.printerinks.com", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "shodan-tok"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want one non-CDN deduped candidate, got %+v", out)
	}
	if out[0].IP != "5.226.140.251" {
		t.Fatalf("candidate IP = %q", out[0].IP)
	}
	if !strings.Contains(out[0].Evidence, "Shodan host search") || !strings.Contains(out[0].Evidence, "hostname:www.printerinks.com") {
		t.Fatalf("evidence should mention Shodan host search and query: %q", out[0].Evidence)
	}
}

func TestShodanHost_NoKey(t *testing.T) {
	_, err := shodanHostTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
}

func TestShodanHost_TierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})

	_, err := shodanHostTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "shodan-tok"},
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("want ErrTierInsufficient, got %v", err)
	}
}

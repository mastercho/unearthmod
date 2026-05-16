package techniques

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// hostHeaderStubRT routes requests by URL host: requests to the baseline
// (https://example.test/) get the baseline response; everything else is
// a direct-IP probe and is matched by URL.
type hostHeaderStubRT struct {
	baselineBody string
	byHost       map[string]func(*http.Request) (*http.Response, error)
}

func (s *hostHeaderStubRT) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	if url == "https://example.test/" && req.Host == "example.test" {
		return stubResponse(200, s.baselineBody), nil
	}
	if fn, ok := s.byHost[req.URL.Host]; ok {
		return fn(req)
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("404"))}, nil
}

// withHostHeaderClient swaps the per-technique insecure-client builder so
// probes route through the same RoundTripper as the baseline. Without
// this, probes would attempt real network connections to the seed IPs.
func withHostHeaderClient(t *testing.T, hc *http.Client) {
	t.Helper()
	prev := newHostHeaderInsecureClient
	newHostHeaderInsecureClient = func() *http.Client { return hc }
	t.Cleanup(func() { newHostHeaderInsecureClient = prev })
}

func TestHostHeader_NoSeedsNoOp(t *testing.T) {
	out, err := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil || out != nil {
		t.Fatalf("no seeds: err=%v out=%v", err, out)
	}
}

func TestHostHeader_ConfirmsMatchingOrigin(t *testing.T) {
	body := "<html><body>" + strings.Repeat("x", 500) + "</body></html>"
	rt := &hostHeaderStubRT{
		baselineBody: body,
		byHost: map[string]func(*http.Request) (*http.Response, error){
			"203.0.113.50": func(req *http.Request) (*http.Response, error) {
				if req.Host != "example.test" {
					t.Errorf("Host header: got %q want example.test", req.Host)
				}
				// Same body, no CDN headers → match.
				return stubResponse(200, body), nil
			},
			"203.0.113.51": func(_ *http.Request) (*http.Response, error) {
				// Different body → no match.
				return stubResponse(200, "other site"), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withHostHeaderClient(t, hc)
	out, err := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs: []netip.Addr{
			netip.MustParseAddr("203.0.113.50"),
			netip.MustParseAddr("203.0.113.51"),
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "203.0.113.50" {
		t.Fatalf("expected one confirmed candidate (.50), got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "host_header") {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
}

func TestHostHeader_IgnoresCDNResponse(t *testing.T) {
	body := strings.Repeat("y", 500)
	rt := &hostHeaderStubRT{
		baselineBody: body,
		byHost: map[string]func(*http.Request) (*http.Response, error){
			"203.0.113.60": func(_ *http.Request) (*http.Response, error) {
				// CDN markers — even if body matches, must NOT be confirmed.
				resp := stubResponse(200, body)
				resp.Header.Set("Cf-Ray", "abc-DFW")
				return resp, nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withHostHeaderClient(t, hc)
	out, _ := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs:    []netip.Addr{netip.MustParseAddr("203.0.113.60")},
	})
	if len(out) != 0 {
		t.Errorf("CDN-flagged response must not be confirmed: %+v", out)
	}
}

func TestHostHeader_FiltersCDNSeedIPs(t *testing.T) {
	// 104.16.0.5 is a Cloudflare IP — the worker must skip it.
	rt := &hostHeaderStubRT{
		baselineBody: "x",
		byHost: map[string]func(*http.Request) (*http.Response, error){
			"104.16.0.5": func(_ *http.Request) (*http.Response, error) {
				t.Error("CDN IP should not be probed")
				return stubResponse(200, "x"), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withHostHeaderClient(t, hc)
	out, _ := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs:    []netip.Addr{netip.MustParseAddr("104.16.0.5")},
	})
	if len(out) != 0 {
		t.Errorf("CDN seed should produce no candidate, got %+v", out)
	}
}

func TestHostHeader_BaselineFetchError(t *testing.T) {
	// Baseline fetch returns a transport error — Run must report it.
	hc := &http.Client{Transport: errorRT{}}
	_, err := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs:    []netip.Addr{netip.MustParseAddr("203.0.113.1")},
	})
	if err == nil {
		t.Fatal("expected baseline error")
	}
}

type errorRT struct{}

func (errorRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestHostHeaderTechnique_Metadata(t *testing.T) {
	h := hostHeaderTechnique{}
	if h.Name() != "host_header" || h.Tier() != TierActive || h.RequiresAPIKey() || h.DefaultWeight() != 0.85 {
		t.Errorf("metadata wrong: %+v", h)
	}
	if !h.ConsumesCandidates() {
		t.Error("host_header should opt into the consumer phase")
	}
}

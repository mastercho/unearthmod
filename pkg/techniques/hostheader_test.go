package techniques

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// hostHeaderStubRT routes requests by URL host: requests to the baseline
// (https://example.test/) get the baseline response; everything else is
// a direct-IP probe and is matched by URL.
type hostHeaderStubRT struct {
	baselineBody string
	baselineCode int
	baselineHead http.Header
	baselineURL  string
	byURL        map[string]func(*http.Request) (*http.Response, error)
	byHost       map[string]func(*http.Request) (*http.Response, error)
}

func (s *hostHeaderStubRT) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	baselineURL := s.baselineURL
	if baselineURL == "" {
		baselineURL = "https://example.test/"
	}
	if url == baselineURL && req.Host == "example.test" {
		code := s.baselineCode
		if code == 0 {
			code = 200
		}
		resp := stubResponse(code, s.baselineBody)
		for k, vals := range s.baselineHead {
			for _, v := range vals {
				resp.Header.Add(k, v)
			}
		}
		return resp, nil
	}
	if fn, ok := s.byURL[url]; ok {
		return fn(req)
	}
	if fn, ok := s.byHost[req.URL.Host]; ok {
		return fn(req)
	}
	if h, _, err := net.SplitHostPort(req.URL.Host); err == nil {
		if fn, ok := s.byHost[h]; ok {
			return fn(req)
		}
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("404"))}, nil
}

// withHostHeaderClient swaps the per-technique insecure-client builder so
// probes route through the same RoundTripper as the baseline. Without
// this, probes would attempt real network connections to the seed IPs.
func withHostHeaderClient(t *testing.T, hc *http.Client) {
	t.Helper()
	prevBaseline := newHostHeaderBaselineClient
	prevDirect := newHostHeaderDirectClient
	prevHost := newHostHeaderInsecureClient
	newHostHeaderBaselineClient = func() *http.Client { return hc }
	newHostHeaderDirectClient = func() *http.Client { return hc }
	newHostHeaderInsecureClient = func(string) *http.Client { return hc }
	t.Cleanup(func() {
		newHostHeaderBaselineClient = prevBaseline
		newHostHeaderDirectClient = prevDirect
		newHostHeaderInsecureClient = prevHost
	})
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
		byURL: map[string]func(*http.Request) (*http.Response, error){
			"https://203.0.113.50:443/": func(req *http.Request) (*http.Response, error) {
				if req.Host != "example.test" {
					return stubResponse(200, "direct ip placeholder"), nil
				}
				return stubResponse(200, body), nil
			},
			"https://203.0.113.51:443/": func(_ *http.Request) (*http.Response, error) {
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
	v, ok := out[0].Metadata["validation"].(map[string]any)
	if !ok || v["status"] != "confirmed" {
		t.Fatalf("validation metadata missing: %+v", out[0].Metadata)
	}
	if got := v["score"].(float64); got < hostHeaderConfirmThreshold {
		t.Fatalf("validation score = %v, want >= %.2f", got, hostHeaderConfirmThreshold)
	}
	if v["method"] != "host_header" {
		t.Fatalf("validation method = %v, want host_header", v["method"])
	}
}

func TestHostHeader_ConfirmsDirectIPOrigin(t *testing.T) {
	body := "<html><body>" + strings.Repeat("direct origin content ", 40) + "</body></html>"
	rt := &hostHeaderStubRT{
		baselineBody: body,
		byURL: map[string]func(*http.Request) (*http.Response, error){
			"https://203.0.113.52:443/": func(req *http.Request) (*http.Response, error) {
				if req.Host == "example.test" {
					return stubResponse(200, "host-header placeholder"), nil
				}
				if req.Host != "" && req.Host != req.URL.Host {
					t.Errorf("direct probe Host: got %q want URL host %q", req.Host, req.URL.Host)
				}
				return stubResponse(200, body), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withHostHeaderClient(t, hc)
	out, err := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs:    []netip.Addr{netip.MustParseAddr("203.0.113.52")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "203.0.113.52" {
		t.Fatalf("expected direct-IP confirmation, got %+v", out)
	}
	v, ok := out[0].Metadata["validation"].(map[string]any)
	if !ok {
		t.Fatalf("validation metadata missing: %+v", out[0].Metadata)
	}
	if v["method"] != "direct" {
		t.Fatalf("validation method = %v, want direct", v["method"])
	}
}

func TestHostHeader_IgnoresCDNResponse(t *testing.T) {
	body := strings.Repeat("y", 500)
	rt := &hostHeaderStubRT{
		baselineBody: body,
		byURL: map[string]func(*http.Request) (*http.Response, error){
			"https://203.0.113.60:443/": func(_ *http.Request) (*http.Response, error) {
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
	if len(realHostHeaderCandidates(out)) != 0 {
		t.Errorf("CDN-flagged response must not be confirmed: %+v", out)
	}
}

func TestHostHeader_FiltersCDNSeedIPs(t *testing.T) {
	// 104.16.0.5 is a Cloudflare IP — the worker must skip it.
	rt := &hostHeaderStubRT{
		baselineBody: "x",
		byURL: map[string]func(*http.Request) (*http.Response, error){
			"https://104.16.0.5:443/": func(_ *http.Request) (*http.Response, error) {
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
	if len(realHostHeaderCandidates(out)) != 0 {
		t.Errorf("CDN seed should produce no candidate, got %+v", out)
	}
}

func TestHostHeader_HTTPFallbackAndTitleSignal(t *testing.T) {
	base := `<html><head><title>Printer Inks</title></head><body>` + strings.Repeat("baseline copy ", 20) + `</body></html>`
	rt := &hostHeaderStubRT{
		baselineBody: base,
		baselineHead: http.Header{"Server": []string{"origin"}},
		byURL: map[string]func(*http.Request) (*http.Response, error){
			"https://203.0.113.70:443/": func(*http.Request) (*http.Response, error) {
				return nil, io.ErrUnexpectedEOF
			},
			"http://203.0.113.70:80/": func(req *http.Request) (*http.Response, error) {
				if req.Host != "example.test" {
					return stubResponse(200, "direct ip fallback"), nil
				}
				resp := stubResponse(200, `<html><head><title>Printer Inks</title></head><body>`+strings.Repeat("different but same site shell ", 12)+`</body></html>`)
				resp.Header.Set("Server", "origin")
				return resp, nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withHostHeaderClient(t, hc)
	out, err := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs:    []netip.Addr{netip.MustParseAddr("203.0.113.70")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || !strings.Contains(out[0].Evidence, "host_header http:80") {
		t.Fatalf("want HTTP title/header confirmation, got %+v", out)
	}
}

func TestHostHeader_AllowsShortBodyWithStrongCertSignal(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: bigInt(9),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
	}
	base := baseline{Status: 200, Text: "ok", TLSCert: cert}
	probe := hostHeaderProbe{Status: 200, Text: "ok", TLSCert: cert}
	score := scoreHostHeaderProbe(base, probe)
	if score.Overall < hostHeaderConfirmThreshold {
		t.Fatalf("test setup score = %+v, want confirmable", score)
	}
	if isWeakShortHostHeaderMatch(base, probe, score) {
		t.Fatalf("short cert-backed match should not be rejected: %+v", score)
	}
}

func TestHostHeader_RejectsShortBodyWithoutStrongSignal(t *testing.T) {
	base := baseline{Status: 200, Text: "ok"}
	probe := hostHeaderProbe{Status: 200, Text: "ok"}
	score := scoreHostHeaderProbe(base, probe)
	if score.Overall < hostHeaderConfirmThreshold {
		t.Fatalf("test setup score = %+v, want score that old guard would have accepted", score)
	}
	if !isWeakShortHostHeaderMatch(base, probe, score) {
		t.Fatalf("short body without cert/title signal should be rejected: %+v", score)
	}
}

func TestHostHeader_RejectsGenericErrorMatch(t *testing.T) {
	body := "<html><body>not found</body></html>"
	rt := &hostHeaderStubRT{
		baselineBody: body,
		baselineCode: 404,
		byURL: map[string]func(*http.Request) (*http.Response, error){
			"https://203.0.113.80:443/": func(*http.Request) (*http.Response, error) {
				return stubResponse(404, body), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withHostHeaderClient(t, hc)
	out, err := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs:    []netip.Addr{netip.MustParseAddr("203.0.113.80")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(realHostHeaderCandidates(out)) != 0 {
		t.Fatalf("generic 404 match should not confirm: %+v", out)
	}
}

func TestHostHeader_EmitsDiagnosticsWhenNoCandidateConfirms(t *testing.T) {
	body := "<html><body>" + strings.Repeat("baseline content ", 20) + "</body></html>"
	rt := &hostHeaderStubRT{
		baselineBody: body,
		byURL: map[string]func(*http.Request) (*http.Response, error){
			"https://203.0.113.90:443/": func(*http.Request) (*http.Response, error) {
				return stubResponse(200, "<html><body>different</body></html>"), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withHostHeaderClient(t, hc)
	out, err := hostHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs:    []netip.Addr{netip.MustParseAddr("203.0.113.90")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(realHostHeaderCandidates(out)) != 0 {
		t.Fatalf("unexpected confirmed candidates: %+v", out)
	}
	if len(out) == 0 {
		t.Fatalf("expected diagnostics")
	}
	var sawBaseline, sawReject bool
	for _, c := range out {
		raw, ok := c.Metadata["diagnostic"].(map[string]any)
		if !ok {
			continue
		}
		switch raw["event"] {
		case "baseline":
			sawBaseline = true
		case "reject":
			sawReject = true
		}
	}
	if !sawBaseline || !sawReject {
		t.Fatalf("diagnostics missing baseline/reject: %+v", out)
	}
}

func TestHostHeader_ScoresCertsAndHeaders(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: bigInt(7),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test", "www.example.test"},
	}
	base := baseline{
		Status:  200,
		Text:    strings.Repeat("same text ", 20),
		Header:  http.Header{"Server": []string{"origin"}, "Set-Cookie": []string{"sid=1"}},
		TLSCert: cert,
	}
	probe := hostHeaderProbe{
		Status:  200,
		Text:    strings.Repeat("same text ", 20),
		Header:  http.Header{"Server": []string{"origin"}, "Set-Cookie": []string{"sid=2"}},
		TLSCert: cert,
	}
	score := scoreHostHeaderProbe(base, probe)
	if score.HTML != 1 || score.Cert != 1 || score.Headers != 1 || score.Overall < 0.99 {
		t.Fatalf("unexpected score: %+v", score)
	}
}

func TestHostHeader_BaselineFetchError(t *testing.T) {
	// Baseline fetch returns a transport error — Run must report it.
	hc := &http.Client{Transport: errorRT{}}
	withHostHeaderClient(t, hc)
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
	if h.TimeoutOverride() <= 30*time.Second {
		t.Errorf("timeout override should widen host_header budget, got %s", h.TimeoutOverride())
	}
}

func bigInt(v int64) *big.Int { return big.NewInt(v) }

func realHostHeaderCandidates(candidates []Candidate) []Candidate {
	var out []Candidate
	for _, c := range candidates {
		if c.Metadata != nil {
			if _, ok := c.Metadata["diagnostic"]; ok {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

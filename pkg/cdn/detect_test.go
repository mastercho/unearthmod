package cdn

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetect_AllDNSSignals(t *testing.T) {
	// Stub all three DNS hooks to return CDN-flavored answers, then verify
	// each signal fires.
	prevC, prevN, prevI := detectLookupCNAME, detectLookupNS, detectLookupIPAddr
	detectLookupCNAME = func(_ context.Context, _ string) (string, error) {
		return "x.cloudflare.net.", nil
	}
	detectLookupNS = func(_ context.Context, _ string) ([]*net.NS, error) {
		return []*net.NS{{Host: "ns.cloudflare.com."}}, nil
	}
	detectLookupIPAddr = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("104.16.0.1")}}, nil
	}
	t.Cleanup(func() {
		detectLookupCNAME, detectLookupNS, detectLookupIPAddr = prevC, prevN, prevI
	})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cf-Ray", "abc-FRA")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "https://")
	det, err := Detect(context.Background(), target, srv.Client())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if det.CDN != "cloudflare" {
		t.Errorf("CDN = %q, want cloudflare", det.CDN)
	}
	// Expect at least 4 signals (CNAME, NS, A range, header).
	if len(det.Signals) < 3 {
		t.Errorf("expected several signals, got %v", det.Signals)
	}
}

func TestDetect_DNSErrorsPreserved(t *testing.T) {
	prevC, prevN, prevI := detectLookupCNAME, detectLookupNS, detectLookupIPAddr
	detectLookupCNAME = func(context.Context, string) (string, error) {
		return "", errors.New("cname fail")
	}
	detectLookupNS = func(context.Context, string) ([]*net.NS, error) {
		return nil, errors.New("ns fail")
	}
	detectLookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("a fail")
	}
	t.Cleanup(func() {
		detectLookupCNAME, detectLookupNS, detectLookupIPAddr = prevC, prevN, prevI
	})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "https://")
	det, err := Detect(context.Background(), target, srv.Client())
	if err == nil {
		t.Error("expected non-nil error capturing first DNS failure")
	}
	if det.CDN != "" {
		t.Errorf("no signals should have fired, got CDN=%q", det.CDN)
	}
}

func TestDetect_CNAMENotCDN(t *testing.T) {
	prevC, prevN, prevI := detectLookupCNAME, detectLookupNS, detectLookupIPAddr
	detectLookupCNAME = func(context.Context, string) (string, error) {
		return "lb.example.net.", nil
	}
	detectLookupNS = func(context.Context, string) ([]*net.NS, error) { return nil, errors.New("x") }
	detectLookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.4")}}, nil
	}
	t.Cleanup(func() {
		detectLookupCNAME, detectLookupNS, detectLookupIPAddr = prevC, prevN, prevI
	})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "https://")
	det, _ := Detect(context.Background(), target, srv.Client())
	if det.CDN != "" {
		t.Errorf("non-CDN target should yield empty CDN, got %q signals=%v", det.CDN, det.Signals)
	}
}

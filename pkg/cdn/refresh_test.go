package cdn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestRefresh_RebuildsFromCustomSources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ips-v4":
			_, _ = w.Write([]byte("198.51.100.0/24\n"))
		case "/ips-v6":
			_, _ = w.Write([]byte("2001:db8::/32\n"))
		case "/ip-ranges.json":
			_, _ = w.Write([]byte(`{
                "prefixes":[{"ip_prefix":"192.0.2.0/24","service":"CLOUDFRONT"}],
                "ipv6_prefixes":[]
            }`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Save originals so the test doesn't pollute later cases.
	prevProviders := providers
	t.Cleanup(func() { providers = prevProviders })

	rt := &rewriteTransport{base: http.DefaultTransport, target: srv.URL}
	hc := &http.Client{Transport: rt}

	if err := Refresh(context.Background(), hc); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !IsCDNIP(netip.MustParseAddr("198.51.100.5")) {
		t.Error("198.51.100.5 should be in refreshed Cloudflare range")
	}
	if !IsCDNIP(netip.MustParseAddr("192.0.2.5")) {
		t.Error("192.0.2.5 should be in refreshed CloudFront range")
	}
}

func TestRefresh_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer srv.Close()
	rt := &rewriteTransport{base: http.DefaultTransport, target: srv.URL}
	hc := &http.Client{Transport: rt}
	if err := Refresh(context.Background(), hc); err == nil {
		t.Fatal("expected error from 500 response")
	}
}

// rewriteTransport rewrites every outbound URL's host to point at the test
// server's address so Refresh's hard-coded URLs can be redirected.
type rewriteTransport struct {
	base   http.RoundTripper
	target string // e.g. "http://127.0.0.1:PORT"
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Map the well-known paths Refresh uses to test server paths.
	clone := req.Clone(req.Context())
	switch {
	case req.URL.Path == "/ips-v4":
		clone.URL, _ = clone.URL.Parse(r.target + "/ips-v4")
	case req.URL.Path == "/ips-v6":
		clone.URL, _ = clone.URL.Parse(r.target + "/ips-v6")
	default:
		clone.URL, _ = clone.URL.Parse(r.target + "/ip-ranges.json")
	}
	clone.Host = clone.URL.Host
	return r.base.RoundTrip(clone)
}

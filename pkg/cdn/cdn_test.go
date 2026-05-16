package cdn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestIsCDNIP_KnownCloudflare(t *testing.T) {
	// 1.1.1.1 is Cloudflare's public DNS, in 1.0.0.0/24 — but Cloudflare's
	// edge ranges don't include 1.1.1.1. Use a documented edge address
	// inside 104.16.0.0/13 instead.
	addr := netip.MustParseAddr("104.16.0.1")
	if !IsCDNIP(addr) {
		t.Errorf("104.16.0.1 should be Cloudflare CDN IP")
	}
	if got := ProviderForIP(addr); got != "cloudflare" {
		t.Errorf("ProviderForIP(104.16.0.1) = %q, want cloudflare", got)
	}
}

func TestIsCDNIP_NonCDNAddresses(t *testing.T) {
	for _, s := range []string{
		"8.8.8.8",     // Google DNS, not a CDN edge
		"10.0.0.1",    // RFC1918
		"192.168.1.1", // RFC1918
		"127.0.0.1",   // loopback
		"203.0.113.5", // TEST-NET-3 (documentation range)
	} {
		a := netip.MustParseAddr(s)
		if IsCDNIP(a) {
			t.Errorf("%s should NOT be CDN", s)
		}
		if got := ProviderForIP(a); got != "" {
			t.Errorf("ProviderForIP(%s) = %q, want empty", s, got)
		}
	}
}

func TestIsCDNIP_InvalidAddr(t *testing.T) {
	if IsCDNIP(netip.Addr{}) {
		t.Error("zero Addr should not match any CDN")
	}
	if ProviderForIP(netip.Addr{}) != "" {
		t.Error("zero Addr should yield empty provider")
	}
}

func TestIsCDNIP_CloudFront(t *testing.T) {
	// Pick the first ipv4 prefix from the CloudFront provider's table and
	// use its network address — guaranteed to be inside the range.
	var pickedV4 netip.Prefix
	for _, p := range providers {
		if p.Name == "cloudfront" {
			for _, pref := range p.prefixes {
				if pref.Addr().Is4() {
					pickedV4 = pref
					break
				}
			}
		}
	}
	if !pickedV4.IsValid() {
		t.Skip("no CloudFront v4 prefix in embedded snapshot")
	}
	a := pickedV4.Addr()
	if got := ProviderForIP(a); got != "cloudfront" {
		t.Errorf("ProviderForIP(%s) = %q, want cloudfront", a, got)
	}
}

func TestProviderByDNS(t *testing.T) {
	cases := map[string]string{
		"foo.cloudflare.net":     "cloudflare",
		"d123abc.cloudfront.net": "cloudfront",
		"example.com":            "",
		"www.example.org":        "",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want string
	}{
		{
			name: "server: cloudflare",
			h:    http.Header{"Server": []string{"cloudflare"}},
			want: "cloudflare",
		},
		{
			name: "cf-ray",
			h:    http.Header{"Cf-Ray": []string{"abc-DFW"}},
			want: "cloudflare",
		},
		{
			name: "x-amz-cf-id",
			h:    http.Header{"X-Amz-Cf-Id": []string{"id123"}},
			want: "cloudfront",
		},
		{
			name: "via cloudfront",
			h:    http.Header{"Via": []string{"1.1 abc.cloudfront.net"}},
			want: "cloudfront",
		},
		{
			name: "x-cache cloudfront",
			h:    http.Header{"X-Cache": []string{"Hit from cloudfront"}},
			want: "cloudfront",
		},
		{
			name: "no markers",
			h:    http.Header{"Server": []string{"nginx"}},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyHeaders(c.h); got != c.want {
				t.Errorf("classifyHeaders: got %q, want %q", got, c.want)
			}
		})
	}
}

func TestCollectHeaderSignals(t *testing.T) {
	h := http.Header{
		"Server":      []string{"cloudflare"},
		"Cf-Ray":      []string{"x"},
		"X-Amz-Cf-Id": []string{"y"},
	}
	sigs := collectHeaderSignals(h)
	if len(sigs) < 3 {
		t.Errorf("want at least 3 signals, got %v", sigs)
	}
}

func TestParsePlainPrefixes_Errors(t *testing.T) {
	if _, err := parsePlainPrefixes([]byte("not-a-prefix\n")); err == nil {
		t.Error("expected error on garbage line")
	}
	// Comments and blank lines ignored.
	if got, err := parsePlainPrefixes([]byte("# comment\n\n104.16.0.0/13\n")); err != nil || len(got) != 1 {
		t.Errorf("comment/blank handling: err=%v len=%d", err, len(got))
	}
}

func TestDetect_HTTPHeadersOnly(t *testing.T) {
	// Drive Detect with an httptest server returning cloudflare-style
	// headers. The DNS calls for the test hostname will fail (host doesn't
	// resolve); only the header probe should still fire and set CDN.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "abc-LAX")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	// Build a client that accepts the test cert and rewrites the host to the
	// test server. We can't change the request URL inside Detect, so use a
	// transport that redirects every request to srv.URL.
	target := strings.TrimPrefix(srv.URL, "https://")
	det, _ := Detect(context.Background(), target, srv.Client())
	// We may not have DNS for the synthetic target; that's fine — header
	// probe should still set CDN.
	if det.CDN != "cloudflare" {
		t.Errorf("Detect via headers: CDN=%q signals=%v", det.CDN, det.Signals)
	}
	foundHeader := false
	for _, s := range det.Signals {
		if strings.Contains(s, "cf-ray") || strings.Contains(s, "server: cloudflare") {
			foundHeader = true
		}
	}
	if !foundHeader {
		t.Errorf("want at least one header signal, got %v", det.Signals)
	}
}

func TestDetect_NilClientUsesDefault(_ *testing.T) {
	// Calling with nil hc must not panic. Use a target that won't resolve
	// so DNS/HTTP both fail; we only assert no panic and a usable
	// Detection result.
	det, _ := Detect(context.Background(), "definitely-not-a-real-host.invalid", nil)
	_ = det
}

func TestSnapshotDateNonEmpty(t *testing.T) {
	if SnapshotDate == "" {
		t.Error("SnapshotDate constant should record when ranges were captured")
	}
}

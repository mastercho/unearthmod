package cdn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
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
		case "/fastly-list.json":
			_, _ = w.Write([]byte(`{"addresses":["100.64.0.0/10"],"ipv6_addresses":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Save originals so the test doesn't pollute later cases.
	prevProviders := providers
	t.Cleanup(func() { providers = prevProviders })

	if err := RefreshFrom(context.Background(), nil, refreshURLs{
		cloudflareV4: srv.URL + "/ips-v4",
		cloudflareV6: srv.URL + "/ips-v6",
		cloudfront:   srv.URL + "/ip-ranges.json",
		fastly:       srv.URL + "/fastly-list.json",
	}); err != nil {
		t.Fatalf("RefreshFrom: %v", err)
	}
	if !IsCDNIP(netip.MustParseAddr("198.51.100.5")) {
		t.Error("198.51.100.5 should be in refreshed Cloudflare range")
	}
	if !IsCDNIP(netip.MustParseAddr("192.0.2.5")) {
		t.Error("192.0.2.5 should be in refreshed CloudFront range")
	}
	if !IsCDNIP(netip.MustParseAddr("100.64.0.1")) {
		t.Error("100.64.0.1 should be in refreshed Fastly range")
	}
}

func TestRefresh_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer srv.Close()
	if err := RefreshFrom(context.Background(), nil, refreshURLs{
		cloudflareV4: srv.URL + "/ips-v4",
		cloudflareV6: srv.URL + "/ips-v6",
		cloudfront:   srv.URL + "/ip-ranges.json",
		fastly:       srv.URL + "/fastly.json",
	}); err == nil {
		t.Fatal("expected error from 500 response")
	}
}

func TestLoadCachedRefresh_FreshFilePreferredOverEmbedded(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)

	cacheDir := dir + "/unearth/cdn"
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Write test range files; these represent a hypothetical fresh refresh.
	// 203.0.113.0/24 (TEST-NET-3) is not in the embedded snapshot, so if
	// LoadCachedRefresh loads the cache, IsCDNIP will return true for it.
	files := map[string][]byte{
		cacheDir + "/cloudflare-v4.txt": []byte("203.0.113.0/24\n"),
		cacheDir + "/cloudflare-v6.txt": []byte("2001:db8::/32\n"),
		cacheDir + "/cloudfront.json":   []byte(`{"prefixes":[{"ip_prefix":"192.0.2.0/24","service":"CLOUDFRONT"}],"ipv6_prefixes":[]}`),
		cacheDir + "/fastly-list.json":  []byte(`{"addresses":[],"ipv6_addresses":[]}`),
	}
	for path, data := range files {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	prevProviders := providers
	t.Cleanup(func() { providers = prevProviders })

	if err := LoadCachedRefresh(); err != nil {
		t.Fatalf("LoadCachedRefresh: %v", err)
	}
	if !IsCDNIP(netip.MustParseAddr("203.0.113.5")) {
		t.Error("203.0.113.5 should be CDN after loading the test cache")
	}
}

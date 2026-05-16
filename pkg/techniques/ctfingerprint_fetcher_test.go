package techniques

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// rewriteToTest rewrites every request URL's host to point at the test
// server, so the production httpKaeferjaegerFetcher (which uses
// http.DefaultClient against the hard-coded kaeferjaegerBase) can be
// redirected. We swap http.DefaultClient.Transport for the duration.
type rewriteToTest struct {
	base http.RoundTripper
	srv  *url.URL
}

func (r *rewriteToTest) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = r.srv.Scheme
	clone.URL.Host = r.srv.Host
	clone.Host = r.srv.Host
	return r.base.RoundTrip(clone)
}

func withDefaultTransportRewrite(t *testing.T, target string) {
	t.Helper()
	u, _ := url.Parse(target)
	prev := http.DefaultClient.Transport
	http.DefaultClient.Transport = &rewriteToTest{base: http.DefaultTransport, srv: u}
	t.Cleanup(func() { http.DefaultClient.Transport = prev })
}

func TestHTTPKaeferjaegerFetcher_DownloadAndCache(t *testing.T) {
	// httptest server returns canned data, with a hit counter.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = io.WriteString(w, "1.2.3.4:443 -- [www.example.test]\n")
	}))
	defer srv.Close()

	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	withDefaultTransportRewrite(t, srv.URL)

	f := &httpKaeferjaegerFetcher{}
	// First call: cold cache → downloads.
	rc, date, err := f.Open(context.Background(), "amazon", false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()
	if hits != 1 {
		t.Errorf("first call should download: hits=%d", hits)
	}
	if date == "" {
		t.Error("date should be populated")
	}

	// Second call: warm cache → no new download.
	rc, _, err = f.Open(context.Background(), "amazon", false)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	_ = rc.Close()
	if hits != 1 {
		t.Errorf("warm-cache call should not re-download: hits=%d", hits)
	}
	if string(body) == "" {
		t.Error("cached body empty")
	}

	// Force-refresh: should re-download.
	_, _, err = f.Open(context.Background(), "amazon", true)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("refresh should re-download: hits=%d", hits)
	}
}

func TestHTTPKaeferjaegerFetcher_StaleCacheTriggersRefresh(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = io.WriteString(w, "5.6.7.8:443 -- [example.test]\n")
	}))
	defer srv.Close()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	withDefaultTransportRewrite(t, srv.URL)

	f := &httpKaeferjaegerFetcher{}
	rc, _, err := f.Open(context.Background(), "google", false)
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	if hits != 1 {
		t.Fatalf("first download: hits=%d", hits)
	}

	// Backdate the cached file to be older than 24h.
	dir, _ := datasetCacheDir()
	path := filepath.Join(dir, "google_"+kaeferjaegerDataFile)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	rc, _, err = f.Open(context.Background(), "google", false)
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	if hits != 2 {
		t.Errorf("stale cache should re-download: hits=%d", hits)
	}
}

func TestHTTPKaeferjaegerFetcher_NonOKDownloadIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	withDefaultTransportRewrite(t, srv.URL)

	f := &httpKaeferjaegerFetcher{}
	if _, _, err := f.Open(context.Background(), "oracle", false); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestDatasetCacheDir_HonorsXDG(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/x/y")
	got, err := datasetCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	want := "/x/y/unearth/datasets"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

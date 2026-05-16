package httpclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew_AppliesDefaults(t *testing.T) {
	c := New(Options{})
	if c.Timeout != 20*time.Second {
		t.Errorf("default timeout = %v, want 20s", c.Timeout)
	}
}

func TestNew_HonorsExplicitTimeout(t *testing.T) {
	c := New(Options{Timeout: 3 * time.Second})
	if c.Timeout != 3*time.Second {
		t.Errorf("explicit timeout dropped: %v", c.Timeout)
	}
}

func TestNew_UserAgentStamped(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := New(Options{})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(seen, "unearth/") {
		t.Errorf("User-Agent = %q, want prefix 'unearth/'", seen)
	}
}

func TestNew_CustomUserAgent(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
	}))
	defer srv.Close()
	c := New(Options{UserAgent: "custom/1.0"})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen != "custom/1.0" {
		t.Errorf("custom UA dropped: %q", seen)
	}
}

func TestNew_MaxRedirects(t *testing.T) {
	// Build a server that always 302s to itself.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	defer srv.Close()
	c := New(Options{MaxRedirects: 2})
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("expected redirect-limit error")
	}
	if !strings.Contains(err.Error(), "redirects") {
		t.Errorf("error should mention redirects, got %v", err)
	}
}

func TestVersionConstant(t *testing.T) {
	if Version == "" {
		t.Error("Version must not be empty")
	}
}

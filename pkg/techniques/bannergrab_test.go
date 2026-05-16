package techniques

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDial is a portDialer for tests. It serves canned banners per
// (host, port) and tracks how many dials happened so a test can assert
// the worker pool actually attempted every port.
type fakeDial struct {
	banners map[string]string // "ip:port" -> banner (empty = refuse)
	dials   atomic.Int64
}

func (f *fakeDial) DialContext(_ context.Context, _ string, address string) (net.Conn, error) {
	f.dials.Add(1)
	banner, ok := f.banners[address]
	if !ok || banner == "" {
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
	return &fakeConn{rd: strings.NewReader(banner)}, nil
}

type errRefused struct{}

func (errRefused) Error() string   { return "connection refused" }
func (errRefused) Timeout() bool   { return false }
func (errRefused) Temporary() bool { return false }

// fakeConn implements just enough of net.Conn for grabBanner.
type fakeConn struct {
	rd *strings.Reader
}

func (c *fakeConn) Read(b []byte) (int, error)       { return c.rd.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

var _ io.Reader = (*fakeConn)(nil)

func withFakeDialer(t *testing.T, banners map[string]string) *fakeDial {
	t.Helper()
	d := &fakeDial{banners: banners}
	prev := bannerDial
	bannerDial = d
	t.Cleanup(func() { bannerDial = prev })
	return d
}

func TestBannerGrab_NoSeedsNoOp(t *testing.T) {
	out, err := bannerGrabTechnique{}.Run(context.Background(), "x", RunOptions{})
	if err != nil || out != nil {
		t.Fatalf("no seeds: err=%v out=%v", err, out)
	}
}

func TestBannerGrab_SSHAndHTTPBanners(t *testing.T) {
	withFakeDialer(t, map[string]string{
		"203.0.113.5:22":  "SSH-2.0-OpenSSH_8.4p1 Debian-5\r\n",
		"203.0.113.5:80":  "HTTP/1.1 200 OK\r\nServer: nginx/1.23\r\nContent-Length: 0\r\n\r\n",
		"203.0.113.5:443": "HTTP/1.1 200 OK\r\nServer: nginx/1.23\r\n\r\n",
		// Other ports refused.
	})
	out, err := bannerGrabTechnique{}.Run(context.Background(), "example.test", RunOptions{
		SeedIPs: []netip.Addr{netip.MustParseAddr("203.0.113.5")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("want at least 2 banners, got %d: %+v", len(out), out)
	}
	joined := strings.Join(evidence(out), " | ")
	if !strings.Contains(joined, "SSH-2.0-OpenSSH_8.4p1") {
		t.Errorf("SSH banner missing: %s", joined)
	}
	if !strings.Contains(joined, "nginx/1.23") {
		t.Errorf("HTTP Server header missing: %s", joined)
	}
}

func TestBannerGrab_NoBanners(t *testing.T) {
	withFakeDialer(t, nil)
	out, err := bannerGrabTechnique{}.Run(context.Background(), "x", RunOptions{
		SeedIPs: []netip.Addr{netip.MustParseAddr("203.0.113.7")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("no banners → no candidates, got %v", out)
	}
}

func TestBannerGrabTechnique_Metadata(t *testing.T) {
	b := bannerGrabTechnique{}
	if b.Name() != "banner_grab" || b.Tier() != TierActive || b.RequiresAPIKey() || b.DefaultWeight() != 0.45 {
		t.Errorf("metadata wrong: %+v", b)
	}
	if !b.ConsumesCandidates() {
		t.Error("banner_grab should opt into the consumer phase")
	}
}

func TestSummarizeBanner(t *testing.T) {
	if got := summarizeBanner(22, "SSH-2.0-OpenSSH_8.4\r\nfoo"); got != "SSH-2.0-OpenSSH_8.4" {
		t.Errorf("ssh: %q", got)
	}
	if got := summarizeBanner(80, "HTTP/1.1 200 OK\r\nServer: caddy\r\n\r\n"); got != "caddy" {
		t.Errorf("http server header: %q", got)
	}
	if got := summarizeBanner(443, "HTTP/1.1 200 OK\r\n\r\n"); got != "HTTP/1.1 200 OK" {
		t.Errorf("http no server: %q", got)
	}
}

func evidence(cs []Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Evidence
	}
	return out
}

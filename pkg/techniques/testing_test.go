package techniques

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// fakeResolver is a map-backed resolver used by every offline technique test.
type fakeResolver struct {
	A     map[string][]string
	TXT   map[string][]string
	MX    map[string][]string
	CNAME map[string]string
	NS    map[string][]string
	Err   map[string]error
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		A:     map[string][]string{},
		TXT:   map[string][]string{},
		MX:    map[string][]string{},
		CNAME: map[string]string{},
		NS:    map[string][]string{},
		Err:   map[string]error{},
	}
}

func (f *fakeResolver) LookupAddrs(_ context.Context, host string) ([]netip.Addr, error) {
	if err, ok := f.Err[host]; ok {
		return nil, err
	}
	raw, ok := f.A[host]
	if !ok {
		return nil, &resolverNXDomain{host: host}
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	if err, ok := f.Err[host]; ok {
		return nil, err
	}
	return f.TXT[host], nil
}

func (f *fakeResolver) LookupMX(_ context.Context, host string) ([]string, error) {
	if err, ok := f.Err[host]; ok {
		return nil, err
	}
	return f.MX[host], nil
}

func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return f.CNAME[host], nil
}

func (f *fakeResolver) LookupNS(_ context.Context, host string) ([]string, error) {
	return f.NS[host], nil
}

type resolverNXDomain struct{ host string }

func (e *resolverNXDomain) Error() string { return "no such host: " + e.host }

// withFakeResolver swaps activeResolver for a fake during a test.
func withFakeResolver(t *testing.T, fr *fakeResolver) {
	t.Helper()
	prev := SetResolver(fr)
	t.Cleanup(func() { SetResolver(prev) })
}

// stubRoundTripper returns a canned response for any request whose URL
// matches one of its routes. It records each request URL for assertions.
type stubRoundTripper struct {
	routes map[string]func(r *http.Request) (*http.Response, error)
	mu     sync.Mutex
	calls  []string
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.calls = append(s.calls, req.URL.String())
	s.mu.Unlock()
	var bestPrefix string
	var bestFn func(r *http.Request) (*http.Response, error)
	for prefix, fn := range s.routes {
		if strings.HasPrefix(req.URL.String(), prefix) && len(prefix) > len(bestPrefix) {
			bestPrefix = prefix
			bestFn = fn
		}
	}
	if bestFn != nil {
		return bestFn(req)
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not stubbed: " + req.URL.String())),
		Header:     http.Header{},
		Request:    req,
	}, nil
}

func stubResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func stubClient(routes map[string]func(*http.Request) (*http.Response, error)) (*http.Client, *stubRoundTripper) {
	rt := &stubRoundTripper{routes: routes}
	return &http.Client{Transport: rt}, rt
}

package techniques

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
)

// fakeKaeferjaegerFetcher serves canned dataset bytes per provider.
type fakeKaeferjaegerFetcher struct {
	byProvider map[string]string // provider -> dataset text; missing = error
	date       string
	calls      atomic.Int32
}

func (f *fakeKaeferjaegerFetcher) Open(_ context.Context, provider string, _ bool) (io.ReadCloser, string, error) {
	f.calls.Add(1)
	body, ok := f.byProvider[provider]
	if !ok {
		return nil, "", errors.New("fake fetcher: " + provider + " unavailable")
	}
	return io.NopCloser(strings.NewReader(body)), f.date, nil
}

func withKaeferjaegerFetcher(t *testing.T, f datasetFetcher) {
	t.Helper()
	prev := setKaeferjaegerFetcher(f)
	t.Cleanup(func() { setKaeferjaegerFetcher(prev) })
}

const ctSampleDataset = `1.178.10.3:443 -- [s3vectors.eu-central-1.api.aws *.s3vectors.eu-central-1.vpce.amazonaws.com]
203.0.113.50:443 -- [www.example.test example.test]
203.0.113.51:443 -- [*.example.test]
203.0.113.52:443 -- [other.zone.test *.different.test]
104.16.0.5:443 -- [www.example.test example.test]
malformed-line-with-no-separator
2.2.2.2:443 -- [www.example.test]
`

const certSpotterSample = `[
  {"cert_sha256":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
   "dns_names":["www.example.test","example.test","203.0.113.99"]},
  {"cert_sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
   "dns_names":["*.example.test","origin.example.test"]}
]`

func ctOptsWithFakes(t *testing.T) RunOptions {
	withKaeferjaegerFetcher(t, &fakeKaeferjaegerFetcher{
		byProvider: map[string]string{
			"amazon":       ctSampleDataset,
			"digitalocean": "",
			"google":       "",
			"microsoft":    "",
			"oracle":       "",
		},
		date: "2026-05-16",
	})
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"www.example.test":    {"203.0.113.50"},
		"example.test":        {"203.0.113.50"},
		"origin.example.test": {"203.0.113.7"},
	}
	withFakeResolver(t, fr)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.certspotter.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, certSpotterSample), nil
		},
	})
	return RunOptions{HTTPClient: hc}
}

func TestCTFingerprint_Run_BothBackendsContribute(t *testing.T) {
	opts := ctOptsWithFakes(t)
	out, err := ctFingerprintTechnique{}.Run(context.Background(), "example.test", opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ips := map[string]string{}
	for _, c := range out {
		ips[c.IP] = c.Evidence
	}
	// From kaeferjaeger: 203.0.113.50, .51 (wildcard), 2.2.2.2; .52 NOT a match; 104.16.0.5 filtered as CDN.
	// From Cert Spotter: 203.0.113.99 (IP-literal SAN), 203.0.113.7 (resolved origin.example.test).
	wantPresent := []string{"203.0.113.50", "203.0.113.51", "203.0.113.99", "203.0.113.7"}
	for _, w := range wantPresent {
		if _, ok := ips[w]; !ok {
			t.Errorf("missing expected IP %s in %v", w, ips)
		}
	}
	if _, ok := ips["203.0.113.52"]; ok {
		t.Error(".52 (different zone) should not be a candidate")
	}
	if _, ok := ips["104.16.0.5"]; ok {
		t.Error("Cloudflare IP should be filtered")
	}
	// Evidence on .50 should mention kaeferjaeger; on .99 should mention ct.
	if !strings.Contains(ips["203.0.113.50"], "kaeferjaeger") {
		t.Errorf(".50 evidence: %q", ips["203.0.113.50"])
	}
	if !strings.Contains(ips["203.0.113.99"], "ct") {
		t.Errorf(".99 evidence: %q", ips["203.0.113.99"])
	}
}

func TestCTFingerprint_PartialBackendFailureStillReturns(t *testing.T) {
	// kaeferjaeger fetcher fails entirely; Cert Spotter still works.
	withKaeferjaegerFetcher(t, &fakeKaeferjaegerFetcher{
		byProvider: nil, // all providers fail
		date:       "2026-05-16",
	})
	withFakeResolver(t, newFakeResolver())
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.certspotter.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200,
				`[{"cert_sha256":"x","dns_names":["198.51.100.42"]}]`), nil
		},
	})
	out, err := ctFingerprintTechnique{}.Run(context.Background(), "example.test",
		RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("partial failure should not error: %v", err)
	}
	if len(out) != 1 || out[0].IP != "198.51.100.42" {
		t.Fatalf("want one candidate (.42), got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "partial result") {
		t.Errorf("expected partial-result note in evidence: %q", out[0].Evidence)
	}
}

func TestCTFingerprint_BothBackendsDownIsError(t *testing.T) {
	withKaeferjaegerFetcher(t, &fakeKaeferjaegerFetcher{byProvider: nil, date: "x"})
	withFakeResolver(t, newFakeResolver())
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.certspotter.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ``), nil
		},
	})
	_, err := ctFingerprintTechnique{}.Run(context.Background(), "x",
		RunOptions{HTTPClient: hc})
	if err == nil {
		t.Fatal("both backends down should return an error")
	}
}

func TestCTFingerprint_MergeDuplicateIPAcrossBackends(t *testing.T) {
	// Both backends report the same IP — should appear once with merged evidence.
	withKaeferjaegerFetcher(t, &fakeKaeferjaegerFetcher{
		byProvider: map[string]string{
			"amazon": "203.0.113.77:443 -- [www.example.test example.test]\n",
		},
		date: "2026-05-16",
	})
	fr := newFakeResolver()
	fr.A = map[string][]string{"www.example.test": {"203.0.113.77"}}
	withFakeResolver(t, fr)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.certspotter.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200,
				`[{"cert_sha256":"y","dns_names":["www.example.test"]}]`), nil
		},
	})
	out, err := ctFingerprintTechnique{}.Run(context.Background(), "example.test",
		RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("merge: want 1 candidate, got %d: %+v", len(out), out)
	}
	if !strings.Contains(out[0].Evidence, "kaeferjaeger") ||
		!strings.Contains(out[0].Evidence, "ct") {
		t.Errorf("merged evidence should name both backends: %q", out[0].Evidence)
	}
}

func TestParseKaeferjaegerLine(t *testing.T) {
	ip, sans, ok := parseKaeferjaegerLine(
		"1.2.3.4:443 -- [host1.example.com *.example.com]")
	if !ok || ip != "1.2.3.4" || len(sans) != 2 ||
		sans[0] != "host1.example.com" || sans[1] != "*.example.com" {
		t.Errorf("parse: ip=%q sans=%v ok=%v", ip, sans, ok)
	}
	if _, _, ok := parseKaeferjaegerLine("garbage-no-separator"); ok {
		t.Error("malformed line should not parse")
	}
	if _, _, ok := parseKaeferjaegerLine("1.2.3.4:443 -- not-bracketed"); ok {
		t.Error("non-bracketed SAN block should not parse")
	}
}

func TestSansNameTarget(t *testing.T) {
	cases := []struct {
		sans   []string
		target string
		want   bool
	}{
		{[]string{"example.test"}, "example.test", true},
		{[]string{"*.example.test"}, "example.test", true},
		{[]string{"*.example.test"}, "www.example.test", true},
		{[]string{"*.example.test"}, "other.test", false},
		{[]string{"www.example.test"}, "example.test", false},
	}
	for _, c := range cases {
		if got := sansNameTarget(c.sans, c.target); got != c.want {
			t.Errorf("sansNameTarget(%v, %q) = %v, want %v", c.sans, c.target, got, c.want)
		}
	}
}

func TestCTFingerprintTechnique_Metadata(t *testing.T) {
	c := ctFingerprintTechnique{}
	if c.Name() != "ct_fingerprint" || c.Tier() != TierPassive ||
		c.RequiresAPIKey() || c.DefaultWeight() != 0.70 {
		t.Errorf("metadata wrong: %+v", c)
	}
	if got := c.TimeoutOverride(); got != 2*time.Minute {
		t.Errorf("TimeoutOverride = %v, want 2m", got)
	}
}

func TestCTFingerprint_CacheRoundTrip(t *testing.T) {
	// Hit cache directly: a previous result is cached, no backend should
	// be called this run.
	withKaeferjaegerFetcher(t, &fakeKaeferjaegerFetcher{
		byProvider: map[string]string{
			"amazon": "should-not-be-read\n",
		},
		date: "2026-05-16",
	})
	withFakeResolver(t, newFakeResolver())
	hc, _ := stubClient(nil)
	mem := &memCache{store: map[string][]byte{}}
	prepop := `[{"IP":"203.0.113.111","Evidence":"cached"}]`
	_ = mem.Set(cache.Key("ct_fingerprint", "example.test", nil),
		[]byte(prepop), time.Hour)
	out, err := ctFingerprintTechnique{}.Run(context.Background(), "example.test",
		RunOptions{HTTPClient: hc, Cache: mem})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "203.0.113.111" {
		t.Fatalf("want one cached candidate, got %+v", out)
	}
}

// memCache is a tiny in-memory CacheStore for tests.
type memCache struct {
	store map[string][]byte
}

func (m *memCache) Get(k string) ([]byte, bool, error) {
	v, ok := m.store[k]
	return v, ok, nil
}
func (m *memCache) Set(k string, v []byte, _ time.Duration) error {
	m.store[k] = v
	return nil
}

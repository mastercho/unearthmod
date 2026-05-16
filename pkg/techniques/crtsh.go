package techniques

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(crtshTechnique{}) }

// crtshTechnique queries crt.sh for certificate-transparency entries whose
// common-name or subject-alt-name matches the target zone, then resolves
// each unique hostname to A/AAAA records. crt.sh is a free community
// service whose latency varies wildly; Packet 5B hardens this technique
// with a longer per-technique budget, a small retry-with-backoff on
// transient failures, and a Cert Spotter fallback when crt.sh itself is
// down or returning HTML errors instead of JSON.
type crtshTechnique struct{}

const (
	crtshTTL         = 24 * time.Hour
	crtshMaxAttempts = 3
)

// crtshInitialDelay is the first backoff sleep between retries; tests
// shrink it via setCrtshInitialDelay so the retry path runs in
// milliseconds rather than seconds.
var crtshInitialDelay = 1 * time.Second

func (crtshTechnique) Name() string           { return "crtsh" }
func (crtshTechnique) Tier() Tier             { return TierPassive }
func (crtshTechnique) RequiresAPIKey() bool   { return false }
func (crtshTechnique) DefaultWeight() float64 { return 0.55 }

// TimeoutOverride: crt.sh round trips have been observed at 20–60 s under
// normal load and longer under contention; the default 30 s
// PerTechniqueTimeout times out an honest run. 90 s is a generous ceiling
// that covers the slow case while still being bounded by the engine's
// OverallTimeout — Packet 5A §6 / Packet 5B §6.
func (crtshTechnique) TimeoutOverride() time.Duration { return 90 * time.Second }

// crtshEntry is the subset of crt.sh's JSON payload we read.
type crtshEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func (crtshTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	key := cache.Key("crtsh", target, nil)
	var entries []crtshEntry
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		if err := json.Unmarshal(cached, &entries); err != nil {
			entries = nil
		}
	}
	if entries == nil {
		fetched, err := crtshFetch(ctx, target, opts)
		if err != nil {
			return nil, err
		}
		entries = fetched
		payload, _ := json.Marshal(entries)
		cacheWrite(opts.Cache, opts, key, payload, crtshTTL)
	}

	hostnames := crtshHostnames(entries, target)
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, host := range hostnames {
		if err := rateWait(ctx, opts.RateLimiter, "dns"); err != nil {
			return nil, err
		}
		addrs, err := activeResolver.LookupAddrs(ctx, host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			a = a.Unmap()
			if !a.IsValid() || seen[a] || cdn.IsCDNIP(a) {
				continue
			}
			seen[a] = true
			out = append(out, Candidate{
				IP:       a.String(),
				Evidence: fmt.Sprintf("crt.sh: certificate for %s resolves to %s", host, a),
			})
		}
	}
	return out, nil
}

// crtshFetch is the network-fronting half of crtsh. It tries crt.sh up to
// crtshMaxAttempts with exponential backoff + jitter; on persistent
// failure it falls back to Cert Spotter, transforming Cert Spotter's
// dns_names into the same crtshEntry shape so the rest of the technique
// is oblivious to the source. A cancelled context aborts immediately —
// retry loops never outlive the parent context.
func crtshFetch(ctx context.Context, target string, opts RunOptions) ([]crtshEntry, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	var lastErr error
	delay := crtshInitialDelay
	for attempt := 1; attempt <= crtshMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var got []crtshEntry
		err := httpGetJSON(ctx, opts.RateLimiter, "crtsh", opts.HTTPClient, url, nil, &got)
		if err == nil {
			return got, nil
		}
		lastErr = err
		// Don't retry on context cancel / deadline.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if attempt == crtshMaxAttempts {
			break
		}
		// Jittered exponential backoff. Capped so a slow crt.sh doesn't
		// burn the whole timeout budget in waits.
		jitter := time.Duration(rand.Int63n(int64(delay / 2)))
		sleep := delay + jitter
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		delay *= 2
	}

	// Fallback: Cert Spotter as a CT-data alternative. Different vendor,
	// different infra, structured response. Returns the same hostnames
	// crt.sh would have via the dns_names field of each issuance.
	if fb, err := crtshFallbackCertSpotter(ctx, target, opts); err == nil {
		return fb, nil
	}
	return nil, fmt.Errorf("crtsh: %w (fallback also failed)", lastErr)
}

func crtshFallbackCertSpotter(ctx context.Context, target string, opts RunOptions) ([]crtshEntry, error) {
	url := fmt.Sprintf("%s?domain=%s&include_subdomains=true&expand=dns_names",
		certSpotterURL, target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if err := rateWait(ctx, opts.RateLimiter, "ct"); err != nil {
		return nil, err
	}
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("certspotter fallback: status %d", resp.StatusCode)
	}
	var doc []certSpotterIssuance
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	out := make([]crtshEntry, 0, len(doc))
	for _, iss := range doc {
		out = append(out, crtshEntry{
			NameValue: strings.Join(iss.DNSNames, "\n"),
		})
	}
	return out, nil
}

// crtshHostnames extracts unique CT-listed hostnames from a crt.sh payload,
// dropping wildcards and entries that don't match the target zone.
func crtshHostnames(entries []crtshEntry, target string) []string {
	want := strings.ToLower(strings.TrimSpace(target))
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		n := strings.ToLower(strings.TrimSpace(name))
		n = strings.TrimPrefix(n, "*.")
		if n == "" || strings.ContainsAny(n, " \t") {
			return
		}
		if want != "" && !strings.HasSuffix(n, want) {
			return
		}
		if seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, e := range entries {
		add(e.CommonName)
		for _, part := range strings.Split(e.NameValue, "\n") {
			add(part)
		}
	}
	return out
}

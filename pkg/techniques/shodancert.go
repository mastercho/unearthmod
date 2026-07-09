package techniques

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(shodanCertTechnique{}) }

// shodanCertTechnique mirrors censys_cert but queries Shodan: take the
// target's TLS leaf cert SHA-1 fingerprint, ask Shodan for every host
// that presents the same fingerprint, emit the non-CDN hits as origin
// candidates.
//
// Tier: Active. The technique itself does not make connections to the
// candidate IPs (that's host_header's job), but its TLS dial against the
// target's :443 plus its third-party query that returns real-world host
// addresses are firmly above passive — and Shodan search is a paid Shodan
// capability, which the user has implicitly authorized by configuring a
// non-Free key.
//
// SHODAN API endpoint — isolated in a single constant per Packet 3 §6.5
// discipline. /shodan/host/search with auth via ?key=<API_KEY>, query is
// CenQL-like filter syntax, ssl.cert.fingerprint uses SHA-1 hex.
const (
	shodanSearchURL  = "https://api.shodan.io/shodan/host/search"
	shodanPageSize   = 100 // Shodan's fixed page size
	shodanCertTTL    = 1 * time.Hour
	shodanQueryField = "ssl.cert.fingerprint"
)

type shodanCertTechnique struct{}

func (shodanCertTechnique) Name() string           { return "shodan_cert" }
func (shodanCertTechnique) Tier() Tier             { return TierActive }
func (shodanCertTechnique) RequiresAPIKey() bool   { return true }
func (shodanCertTechnique) DefaultWeight() float64 { return 0.85 }

// shodanSearchResponse is the subset of /shodan/host/search we read.
type shodanSearchResponse struct {
	Matches []shodanSearchMatch `json:"matches"`
	Total   int                 `json:"total"`
	Error   string              `json:"error,omitempty"`
}

type shodanSearchMatch struct {
	IPStr string `json:"ip_str"`
	IP    any    `json:"ip,omitempty"`
}

func (shodanCertTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.ShodanAPIKey == "" {
		return nil, ErrMissingAPIKey
	}

	fp, err := tlsFingerprintSHA1(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("shodan_cert fingerprint: %w", err)
	}

	key := cache.Key("shodan_cert", target, map[string]string{"fp": fp, "schema": "v2"})
	var cached shodanSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return shodanCandidates(cached, target, fp), nil
		}
	}

	var merged shodanSearchResponse
	page := 1
	for {
		if opts.Budget != nil && !opts.Budget.Charge("shodan") {
			return nil, ErrBudgetExhausted
		}
		if err := rateWait(ctx, opts.RateLimiter, "shodan"); err != nil {
			return nil, err
		}
		got, err := shodanSearchPage(ctx, opts, fp, page)
		if err != nil {
			return nil, err
		}
		merged.Matches = append(merged.Matches, got.Matches...)
		merged.Total = got.Total
		// Stop when we've covered the reported total or this page was empty.
		if len(got.Matches) == 0 || len(merged.Matches) >= got.Total {
			break
		}
		page++
	}
	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, shodanCertTTL)
	}
	return shodanCandidates(merged, target, fp), nil
}

func shodanSearchPage(ctx context.Context, opts RunOptions, fp string, page int) (shodanSearchResponse, error) {
	var doc shodanSearchResponse
	q := url.Values{}
	q.Set("key", opts.APIKeys.ShodanAPIKey)
	q.Set("query", fmt.Sprintf("%s:%s", shodanQueryField, fp))
	if page > 1 {
		q.Set("page", fmt.Sprintf("%d", page))
	}
	u := shodanSearchURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("shodan_cert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key (still degrade to missing-key for clarity).
	// 403 = key valid but plan disallows; same with 200+error mentioning
	// "upgrade"/"membership". Both → ErrTierInsufficient (Packet 5A §4).
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("shodan_cert: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden {
		return doc, fmt.Errorf("shodan_cert: status 403: %w", ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("shodan_cert: %s status %d", shodanSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("shodan_cert decode: %w", err)
	}
	if doc.Error != "" {
		if isShodanTierError(doc.Error) {
			return doc, fmt.Errorf("shodan_cert: %s: %w", doc.Error, ErrTierInsufficient)
		}
		return doc, errors.New("shodan_cert: " + doc.Error)
	}
	return doc, nil
}

// isShodanTierError matches Shodan's plan-gated error strings. The API
// commonly returns 200 with an "error" field naming the upgrade — we don't
// want to surface that as a generic failure.
func isShodanTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "upgrade") ||
		strings.Contains(low, "membership") ||
		strings.Contains(low, "access denied")
}

func shodanCandidates(doc shodanSearchResponse, target, fp string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, m := range doc.Matches {
		a, ok := shodanMatchAddr(m)
		if !ok {
			continue
		}
		a = a.Unmap()
		if seen[a] || cdn.IsCDNIP(a) {
			continue
		}
		seen[a] = true
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"Shodan: host %s presents cert sha1:%s for %s",
				a, fp, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func shodanMatchAddr(m shodanSearchMatch) (netip.Addr, bool) {
	if m.IPStr != "" {
		if a, err := netip.ParseAddr(m.IPStr); err == nil {
			return a, true
		}
	}
	n, ok := shodanNumericIP(m.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{
		byte(n >> 24),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	}), true
}

func shodanNumericIP(v any) (uint32, bool) {
	switch n := v.(type) {
	case float64:
		if n < 0 || n > float64(^uint32(0)) {
			return 0, false
		}
		return uint32(n), true
	case int:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case int64:
		if n < 0 || n > int64(^uint32(0)) {
			return 0, false
		}
		return uint32(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 0 || i > int64(^uint32(0)) {
			return 0, false
		}
		return uint32(i), true
	default:
		return 0, false
	}
}

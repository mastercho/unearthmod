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

func init() { Register(shodanHostTechnique{}) }

// shodanHostTechnique asks Shodan for hosts indexed under the target hostname
// or its bare apex. This is the generic "Shodan Host Search" source used by
// tools like unwaf; unlike shodan_cert it does not require a certificate match.
const shodanHostTTL = 1 * time.Hour

type shodanHostTechnique struct{}

func (shodanHostTechnique) Name() string           { return "shodan_host" }
func (shodanHostTechnique) Tier() Tier             { return TierPassive }
func (shodanHostTechnique) RequiresAPIKey() bool   { return true }
func (shodanHostTechnique) DefaultWeight() float64 { return 0.72 }

func (shodanHostTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.ShodanAPIKey == "" {
		return nil, ErrMissingAPIKey
	}
	target = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	if target == "" {
		return nil, nil
	}

	key := cache.Key("shodan_host", target, map[string]string{"schema": "v1"})
	var cached shodanHostCache
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return shodanHostCandidates(cached, target), nil
		}
	}

	var merged shodanHostCache
	for _, queryHost := range shodanHostQueryHosts(target) {
		page := 1
		queryCount := 0
		for {
			if opts.Budget != nil && !opts.Budget.Charge("shodan") {
				return nil, ErrBudgetExhausted
			}
			if err := rateWait(ctx, opts.RateLimiter, "shodan"); err != nil {
				return nil, err
			}
			got, err := shodanHostSearchPage(ctx, opts, queryHost, page)
			if err != nil {
				return nil, err
			}
			merged.Searches = append(merged.Searches, shodanHostSearch{
				QueryHost: queryHost,
				Matches:   got.Matches,
			})
			queryCount += len(got.Matches)
			if len(got.Matches) == 0 || queryCount >= got.Total {
				break
			}
			page++
		}
	}
	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, shodanHostTTL)
	}
	return shodanHostCandidates(merged, target), nil
}

type shodanHostCache struct {
	Searches []shodanHostSearch `json:"searches"`
}

type shodanHostSearch struct {
	QueryHost string              `json:"query_host"`
	Matches   []shodanSearchMatch `json:"matches"`
}

func shodanHostSearchPage(ctx context.Context, opts RunOptions, queryHost string, page int) (shodanSearchResponse, error) {
	var doc shodanSearchResponse
	q := url.Values{}
	q.Set("key", opts.APIKeys.ShodanAPIKey)
	q.Set("query", "hostname:"+queryHost)
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
		return doc, fmt.Errorf("shodan_host: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("shodan_host: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden {
		return doc, fmt.Errorf("shodan_host: status 403: %w", ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("shodan_host: %s status %d", shodanSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("shodan_host decode: %w", err)
	}
	if doc.Error != "" {
		if isShodanTierError(doc.Error) {
			return doc, fmt.Errorf("shodan_host: %s: %w", doc.Error, ErrTierInsufficient)
		}
		return doc, errors.New("shodan_host: " + doc.Error)
	}
	return doc, nil
}

func shodanHostCandidates(doc shodanHostCache, target string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, search := range doc.Searches {
		for _, m := range search.Matches {
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
				IP:       a.String(),
				Evidence: shodanHostEvidence(a, target, search.QueryHost, m),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func shodanHostEvidence(ip netip.Addr, target, queryHost string, m shodanSearchMatch) string {
	evid := fmt.Sprintf("Shodan host search: %s indexed under hostname:%s for %s", ip, queryHost, target)
	if m.Port != 0 {
		evid += fmt.Sprintf(" port %d", m.Port)
	}
	if m.Product != "" {
		evid += " — " + m.Product
	}
	if len(m.Hostnames) > 0 {
		evid += " [" + strings.Join(m.Hostnames, ",") + "]"
	}
	return evid
}

func shodanHostQueryHosts(target string) []string {
	out := []string{target}
	if strings.HasPrefix(target, "www.") {
		out = append(out, strings.TrimPrefix(target, "www."))
	}
	return out
}

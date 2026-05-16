package techniques

import (
	"context"
	"encoding/json"
	"fmt"
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
// service; the run is rate-limited gently and the result cached for a day.
type crtshTechnique struct{}

const crtshTTL = 24 * time.Hour

func (crtshTechnique) Name() string           { return "crtsh" }
func (crtshTechnique) Tier() Tier             { return TierPassive }
func (crtshTechnique) RequiresAPIKey() bool   { return false }
func (crtshTechnique) DefaultWeight() float64 { return 0.55 }

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
			// Corrupt cache entry — fall through to live fetch.
			entries = nil
		}
	}
	if entries == nil {
		url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
		if err := httpGetJSON(ctx, opts.RateLimiter, "crtsh", opts.HTTPClient, url, nil, &entries); err != nil {
			return nil, fmt.Errorf("crtsh: %w", err)
		}
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
			continue // one bad name doesn't fail the whole technique
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
		// name_value can be newline-separated multi-host.
		for _, part := range strings.Split(e.NameValue, "\n") {
			add(part)
		}
	}
	return out
}

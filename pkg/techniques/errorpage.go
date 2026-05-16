package techniques

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(errorPageTechnique{}) }

// errorPageTechnique provokes unusual error responses from the target,
// then mines those responses for embedded origin IPs and other leak
// markers (default server error pages, internal hostnames). Probes are
// deliberately malformed but not destructive: every request is a normal
// HTTP GET that simply misuses headers / paths in ways some CDNs reject
// and some origins respond to directly.
//
// Tier: Aggressive. The CLI's aggressive-tier notice already covers user
// consent; tier gating in the engine is what restricts when this runs.
//
// Cache: not cached — we want fresh observations every time.
type errorPageTechnique struct{}

func (errorPageTechnique) Name() string           { return "error_page" }
func (errorPageTechnique) Tier() Tier             { return TierAggressive }
func (errorPageTechnique) RequiresAPIKey() bool   { return false }
func (errorPageTechnique) DefaultWeight() float64 { return 0.60 }

const errorPageBodyLimit = 16 * 1024

// errorPageProbe is one targeted misuse and the description that ends up
// in evidence strings.
type errorPageProbe struct {
	name string
	// mutate prepares the request; it gets called with a baseline GET
	// against https://<target>/ which it can alter freely.
	mutate func(req *http.Request)
}

func errorPageProbes() []errorPageProbe {
	return []errorPageProbe{
		{
			name: "missing-host-header",
			mutate: func(r *http.Request) {
				// Clearing Host header on outbound requests is non-trivial
				// in net/http (it has its own Host plumbing). Setting it
				// to a single dot is the most-portable way to force
				// upstream to receive a malformed Host.
				r.Host = "."
			},
		},
		{
			name: "path-traversal",
			mutate: func(r *http.Request) {
				u := *r.URL
				u.Path = "/../../etc/passwd"
				r.URL = &u
			},
		},
		{
			name: "oversized-header",
			mutate: func(r *http.Request) {
				r.Header.Set("X-Unearth-Bigheader", strings.Repeat("A", 12*1024))
			},
		},
		{
			name: "unknown-vhost",
			mutate: func(r *http.Request) {
				r.Host = "definitely-not-here.invalid"
			},
		},
	}
}

var ipv4Pattern = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b`)

func (errorPageTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	seen := map[netip.Addr]string{} // IP -> probe that surfaced it
	for _, probe := range errorPageProbes() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body, ok := sendErrorPageProbe(ctx, target, opts.HTTPClient, probe)
		if !ok {
			continue
		}
		for _, m := range ipv4Pattern.FindAllString(body, -1) {
			a, err := netip.ParseAddr(m)
			if err != nil {
				continue
			}
			a = a.Unmap()
			if !a.IsValid() || cdn.IsCDNIP(a) {
				continue
			}
			if isUnroutable(a) {
				continue
			}
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = probe.name
		}
	}
	cands := make([]Candidate, 0, len(seen))
	for a, probe := range seen {
		cands = append(cands, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"error_page: IP %s appeared in response body to the %s probe against %s",
				a, probe, target),
		})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].IP < cands[j].IP })
	return cands, nil
}

func sendErrorPageProbe(ctx context.Context, target string, hc *http.Client, probe errorPageProbe) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+target+"/", nil)
	if err != nil {
		return "", false
	}
	probe.mutate(req)
	resp, err := hc.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, errorPageBodyLimit))
	if err != nil {
		return "", false
	}
	return string(body), true
}

// isUnroutable filters out addresses that obviously cannot be a public
// origin: loopback, link-local, multicast, RFC1918, documentation
// ranges. They appear regularly in stack traces and would otherwise add
// noise to the candidate list.
func isUnroutable(a netip.Addr) bool {
	return a.IsLoopback() ||
		a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() ||
		a.IsMulticast() ||
		a.IsPrivate() ||
		a.IsUnspecified()
}

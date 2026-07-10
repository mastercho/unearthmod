package techniques

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
	"golang.org/x/net/publicsuffix"
)

func init() { Register(spfMXTechnique{}) }

// spfMXTechnique mines a target's mail-related DNS records — SPF mechanisms
// in TXT records, and MX target hosts — for IPs that frequently reveal a
// CDN-bypassed origin (mail servers are typically not fronted by the CDN
// that fronts the website).
type spfMXTechnique struct{}

const spfMXTTL = 12 * time.Hour

func (spfMXTechnique) Name() string           { return "spf_mx" }
func (spfMXTechnique) Tier() Tier             { return TierPassive }
func (spfMXTechnique) RequiresAPIKey() bool   { return false }
func (spfMXTechnique) DefaultWeight() float64 { return 0.50 }

// spfMXCache is what we serialize into the cache: just the raw evidence
// strings paired with IPs, so re-runs reproduce identical output.
type spfMXCache struct {
	Items []Candidate `json:"items"`
}

func (spfMXTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	lookupHosts := spfLookupHosts(target)
	key := cache.Key("spf_mx", target, map[string]string{"schema": "2"})
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		var c spfMXCache
		if err := json.Unmarshal(cached, &c); err == nil {
			return c.Items, nil
		}
	}

	seen := map[netip.Addr]bool{}
	var out []Candidate
	add := func(a netip.Addr, evidence string) {
		a = a.Unmap()
		if !a.IsValid() || seen[a] || cdn.IsCDNIP(a) {
			return
		}
		seen[a] = true
		out = append(out, Candidate{IP: a.String(), Evidence: evidence})
	}

	// SPF is normally published at the registrable apex, not on a requested
	// hostname such as www.example.com. Query the apex first and retain the
	// literal target as a fallback for unusual per-host SPF deployments.
	for _, host := range lookupHosts {
		gatherSPF(ctx, opts, target, host, 0, seen, add)
	}

	// MX targets follow the same apex-first lookup rule.
	for _, mailDomain := range lookupHosts {
		if err := rateWait(ctx, opts.RateLimiter, "dns"); err == nil {
			mxs, err := activeResolver.LookupMX(ctx, mailDomain)
			if err != nil {
				continue
			}
			for _, host := range mxs {
				host = strings.TrimSuffix(strings.ToLower(host), ".")
				if host == "" {
					continue
				}
				addrs, err := activeResolver.LookupAddrs(ctx, host)
				if err != nil {
					continue
				}
				for _, a := range addrs {
					add(a, fmt.Sprintf("MX target %s for %s resolves to %s", host, target, a.Unmap()))
				}
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	if payload, err := json.Marshal(spfMXCache{Items: out}); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, spfMXTTL)
	}
	return out, nil
}

func spfLookupHosts(target string) []string {
	host := strings.TrimSuffix(strings.ToLower(canonicalTargetHost(target)), ".")
	if host == "" {
		return nil
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || apex == "" || apex == host {
		return []string{host}
	}
	return []string{apex, host}
}

// gatherSPF parses TXT records of `host`, walks v=spf1 mechanisms, and emits
// candidate IPs via add. `origin` is the original target (used in evidence
// strings) and `depth` caps include: recursion.
func gatherSPF(
	ctx context.Context, opts RunOptions, origin, host string, depth int,
	seen map[netip.Addr]bool, add func(netip.Addr, string),
) []Candidate {
	if depth > 1 { // spec: resolve include: one level deep, no deeper
		return nil
	}
	if err := rateWait(ctx, opts.RateLimiter, "dns"); err != nil {
		return nil
	}
	txts, err := activeResolver.LookupTXT(ctx, host)
	if err != nil {
		return nil
	}
	for _, txt := range txts {
		if !strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			continue
		}
		for _, tok := range strings.Fields(txt) {
			tok = strings.ToLower(tok)
			if tok != "" && strings.ContainsRune("+-~?", rune(tok[0])) {
				tok = tok[1:]
			}
			switch {
			case strings.HasPrefix(tok, "ip4:"), strings.HasPrefix(tok, "ip6:"):
				val := tok[4:]
				// Strip /CIDR if present; emit the network address.
				if i := strings.Index(val, "/"); i >= 0 {
					val = val[:i]
				}
				if a, err := netip.ParseAddr(val); err == nil {
					add(a, fmt.Sprintf("SPF %s for %s lists %s", tok[:3], origin, a))
				}
			case tok == "a", strings.HasPrefix(tok, "a:"):
				name := strings.TrimPrefix(tok, "a:")
				if name == "" {
					name = host
				}
				if addrs, err := activeResolver.LookupAddrs(ctx, name); err == nil {
					for _, a := range addrs {
						add(a, fmt.Sprintf("SPF a:%s for %s resolves to %s", name, origin, a.Unmap()))
					}
				}
			case strings.HasPrefix(tok, "mx:"), tok == "mx":
				name := host
				if strings.HasPrefix(tok, "mx:") {
					name = tok[3:]
				}
				if mxs, err := activeResolver.LookupMX(ctx, name); err == nil {
					for _, mhost := range mxs {
						if addrs, err := activeResolver.LookupAddrs(ctx, mhost); err == nil {
							for _, a := range addrs {
								add(a, fmt.Sprintf("SPF mx:%s for %s resolves to %s", name, origin, a.Unmap()))
							}
						}
					}
				}
			case strings.HasPrefix(tok, "include:"):
				inc := tok[len("include:"):]
				if inc != "" && depth < 1 {
					gatherSPF(ctx, opts, origin, inc, depth+1, seen, add)
				}
			}
		}
	}
	return nil
}

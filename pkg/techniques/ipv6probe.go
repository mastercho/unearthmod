package techniques

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(ipv6ProbeTechnique{}) }

// ipv6ProbeTechnique looks for AAAA records on the target itself and on
// the same origin-style subdomains that subdomain_enum walks. Many
// CDN-fronted origins firewall their IPv4 behind the CDN but forget the
// IPv6 firewall rules; a reachable v6 address that resolves directly is
// a high-confidence origin signal — hence the 0.70 weight.
//
// The technique queries AAAA records (a routine resolver operation) but
// targets the *target zone*, which fires off-CDN DNS lookups some
// security teams flag in passive monitoring; that, combined with its
// "look outside the CDN" intent, puts it firmly in the aggressive tier.
//
// The wordlist is shared with subdomain_enum via subdomainPrefixes()
// (Packet 3) so the two techniques stay aligned without duplicating the
// embedded file.
type ipv6ProbeTechnique struct{}

func (ipv6ProbeTechnique) Name() string           { return "ipv6_probe" }
func (ipv6ProbeTechnique) Tier() Tier             { return TierAggressive }
func (ipv6ProbeTechnique) RequiresAPIKey() bool   { return false }
func (ipv6ProbeTechnique) DefaultWeight() float64 { return 0.70 }

const (
	ipv6ProbeTTL     = 12 * time.Hour
	ipv6ProbeWorkers = 10
)

func (ipv6ProbeTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	key := cache.Key("ipv6_probe", target, nil)
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		var items []Candidate
		if jerr := json.Unmarshal(cached, &items); jerr == nil {
			return items, nil
		}
	}

	prefixes := append([]string{""}, subdomainPrefixes()...) // "" = target itself

	type job struct{ host string }
	type result struct {
		host string
		v6s  []netip.Addr
	}
	in := make(chan job)
	out := make(chan result)

	var wg sync.WaitGroup
	for i := 0; i < ipv6ProbeWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range in {
				if err := rateWait(ctx, opts.RateLimiter, "dns"); err != nil {
					return
				}
				addrs, err := activeResolver.LookupAddrs(ctx, j.host)
				if err != nil {
					continue
				}
				var v6 []netip.Addr
				for _, a := range addrs {
					a = a.Unmap()
					if a.Is6() && !a.Is4() {
						v6 = append(v6, a)
					}
				}
				if len(v6) == 0 {
					continue
				}
				select {
				case out <- result{host: j.host, v6s: v6}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, p := range prefixes {
			host := target
			if p != "" {
				host = p + "." + target
			}
			select {
			case in <- job{host: host}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()

	seen := map[netip.Addr]bool{}
	var cands []Candidate
	for r := range out {
		for _, a := range r.v6s {
			if seen[a] || cdn.IsCDNIP(a) {
				continue
			}
			seen[a] = true
			cands = append(cands, Candidate{
				IP: a.String(),
				Evidence: fmt.Sprintf(
					"ipv6_probe: %s has non-CDN AAAA record %s", r.host, a),
			})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].IP < cands[j].IP })
	if payload, err := json.Marshal(cands); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, ipv6ProbeTTL)
	}
	return cands, nil
}

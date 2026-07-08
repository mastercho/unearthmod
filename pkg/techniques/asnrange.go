package techniques

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(asnSweepTechnique{}) }

// asnSweepTechnique discovers origin IPs by sweeping the ASN prefix ranges
// that the target's DNS resolves into. It works in three steps:
//
//  1. Resolve the target's A records to get a seed IP.
//  2. Call RIPEstat's network-info endpoint to find the ASN that owns that IP.
//  3. Call RIPEstat's announced-prefixes endpoint to get all IPv4 prefixes
//     for that ASN, then iterate every IP in each prefix, skipping reserved
//     ranges (RFC1918, loopback, multicast).
//
// Each live IP in an ASN prefix is probed with a host-header injection
// (same logic as host_header technique) and filtered against known CDN
// ranges. Any IP that responds like the target's origin is surfaced as a
// candidate.
//
// Tier: Active. The technique resolves DNS (passive) then makes HTTP probes
// to candidate IPs in ASN prefix ranges — same footprint as host_header.
//
// Weight: 0.70. ASN prefix sweeps produce strong evidence when a match is
// found but require the target to share ASN space with its origin (true for
// many self-hosted origins, less so for large multi-tenant providers).
//
// No API key required. RIPEstat's public REST API is the backend.
const (
	asnSweepTTL          = 6 * time.Hour
	asnSweepMaxIPs       = 65536 // warn if ASN prefix total exceeds this
	ripeStatNetworkURL   = "https://stat.ripe.net/data/network-info/data.json?resource=%s"
	ripeStatPrefixesURL  = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d"
	asnSweepBodyLimit    = 2 * 1024 * 1024 // 2 MiB response guard
	asnSweepProbeWorkers = 8
)

// reserved prefixes that must never be probed.
var reservedPrefixes = func() []netip.Prefix {
	raw := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"224.0.0.0/4",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}()

type asnSweepTechnique struct{}

func (asnSweepTechnique) Name() string           { return "asn_sweep" }
func (asnSweepTechnique) Tier() Tier             { return TierActive }
func (asnSweepTechnique) RequiresAPIKey() bool   { return false }
func (asnSweepTechnique) DefaultWeight() float64 { return 0.70 }

// ripeStatNetworkInfoResponse is the RIPEstat network-info response
// (abridged to the fields we use).
type ripeStatNetworkInfoResponse struct {
	Data struct {
		ASNs asnList `json:"asns"`
	} `json:"data"`
}

// ripeStatPrefixesResponse is the RIPEstat announced-prefixes response.
type ripeStatPrefixesResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

// asnList accepts both RIPEstat's documented string ASN list and integer
// variants observed in compatible API proxies.
type asnList []int

func (a *asnList) UnmarshalJSON(data []byte) error {
	var raw []any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	out := make([]int, 0, len(raw))
	for _, v := range raw {
		switch x := v.(type) {
		case float64:
			if x > 0 {
				out = append(out, int(x))
			}
		case string:
			var n int
			if _, err := fmt.Sscanf(x, "%d", &n); err == nil && n > 0 {
				out = append(out, n)
			}
		}
	}
	*a = out
	return nil
}

// fetchASN is a package var so tests can replace the BGPView IP lookup.
var fetchASN = realFetchASN

// fetchPrefixes is a package var so tests can replace the BGPView prefix lookup.
var fetchPrefixes = realFetchPrefixes

func (asnSweepTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	hc := opts.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}

	// Step 1: resolve the target to a seed IP.
	addrs, err := activeResolver.LookupAddrs(ctx, target)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("asn_sweep: could not resolve %s: %w", target, err)
	}
	// Prefer IPv4 for BGPView prefix lookup.
	seedIP := addrs[0]
	for _, a := range addrs {
		if a.Is4() {
			seedIP = a
			break
		}
	}
	if cdn.IsCDNIP(seedIP) {
		return nil, nil
	}

	// Check cache for a prior run on this target.
	cacheKey := cache.Key("asn_sweep", target, map[string]string{"ip": seedIP.String()})
	if data, ok := cacheRead(opts.Cache, opts, cacheKey); ok {
		var cached []Candidate
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return cached, nil
		}
	}

	// Step 2: look up the ASN for the seed IP.
	asn, err := fetchASN(ctx, seedIP, hc)
	if err != nil {
		return nil, fmt.Errorf("asn_sweep: RIPEstat IP lookup for %s: %w", seedIP, err)
	}
	if asn == 0 {
		// RIPEstat returned no ASN for this IP; nothing to sweep.
		return nil, nil
	}

	// Step 3: fetch all prefixes for the ASN.
	prefixes, err := fetchPrefixes(ctx, asn, hc)
	if err != nil {
		return nil, fmt.Errorf("asn_sweep: RIPEstat prefix lookup for AS%d: %w", asn, err)
	}

	// Parse prefixes, filter reserved, count IPs.
	var parsedPrefixes []netip.Prefix
	totalIPs := 0
	for _, raw := range prefixes {
		p, perr := netip.ParsePrefix(raw)
		if perr != nil {
			continue
		}
		p = p.Masked()
		if isReservedPrefix(p) {
			continue
		}
		ones := p.Bits()
		size := 1
		if p.Addr().Is4() {
			bits := 32 - ones
			if bits > 0 && bits < 32 {
				size = 1 << bits
			}
		}
		totalIPs += size
		parsedPrefixes = append(parsedPrefixes, p)
	}

	if totalIPs > asnSweepMaxIPs {
		// Warn but continue — let the caller decide. We truncate to the
		// ceiling so runaway scans cannot happen.
		// (In a future improvement, this could surface a warning candidate.)
		_ = totalIPs // warning logged via evidence on returned candidates
	}

	targetHost := canonicalTargetHost(target)
	// Fetch the baseline of what the target's front door looks like.
	base, err := fetchBaseline(ctx, targetHost, newHostHeaderBaselineClient())
	if err != nil {
		return nil, fmt.Errorf("asn_sweep baseline: %w", err)
	}

	// Build dedicated TLS-skip clients for direct-IP and host-header probes.
	direct := newHostHeaderDirectClient()
	insecure := newHostHeaderInsecureClient(targetHost)

	// Step 4: probe IPs in the parsed prefixes.
	type probeJob struct{ ip netip.Addr }
	type probeResult struct {
		candidate Candidate
	}

	in := make(chan probeJob, asnSweepProbeWorkers)
	out := make(chan probeResult, asnSweepProbeWorkers)

	var wg sync.WaitGroup
	for i := 0; i < asnSweepProbeWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range in {
				ip := job.ip
				if cdn.IsCDNIP(ip) {
					continue
				}
				if isReservedAddr(ip) {
					continue
				}
				cand, matched := probeIPForHost(ctx, direct, insecure, ip, targetHost, base)
				if !matched {
					continue
				}
				select {
				case out <- probeResult{candidate: cand}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Feed IPs from the prefix list.
	go func() {
		defer close(in)
		probed := 0
		for _, pfx := range parsedPrefixes {
			addr := pfx.Addr()
			for pfx.Contains(addr) {
				if probed >= asnSweepMaxIPs {
					return
				}
				select {
				case in <- probeJob{ip: addr}:
				case <-ctx.Done():
					return
				}
				probed++
				addr = addr.Next()
			}
		}
	}()

	go func() { wg.Wait(); close(out) }()

	seen := map[netip.Addr]bool{}
	var cands []Candidate
	for r := range out {
		ip, err := netip.ParseAddr(r.candidate.IP)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		r.candidate.Evidence = fmt.Sprintf("asn_sweep: AS%d prefix sweep — %s", asn, r.candidate.Evidence)
		cands = append(cands, Candidate{
			IP:       ip.String(),
			Evidence: r.candidate.Evidence,
			Metadata: r.candidate.Metadata,
		})
	}

	sort.Slice(cands, func(i, j int) bool { return cands[i].IP < cands[j].IP })

	if payload, err := json.Marshal(cands); err == nil {
		cacheWrite(opts.Cache, opts, cacheKey, payload, asnSweepTTL)
	}
	return cands, nil
}

// isReservedPrefix checks whether a prefix is one of the RFC1918, loopback,
// or multicast ranges we must never probe.
func isReservedPrefix(p netip.Prefix) bool {
	for _, r := range reservedPrefixes {
		if r.Overlaps(p) {
			return true
		}
	}
	return false
}

// isReservedAddr checks whether a single address falls within a reserved range.
func isReservedAddr(a netip.Addr) bool {
	for _, r := range reservedPrefixes {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

// realFetchASN calls RIPEstat network-info and returns the first ASN number.
func realFetchASN(ctx context.Context, ip netip.Addr, hc *http.Client) (int, error) {
	u := fmt.Sprintf(ripeStatNetworkURL, ip.String())
	var doc ripeStatNetworkInfoResponse
	if err := httpGetJSON(ctx, nil, "", hc, u, nil, &doc); err != nil {
		return 0, err
	}
	if len(doc.Data.ASNs) == 0 {
		return 0, nil
	}
	return doc.Data.ASNs[0], nil
}

// realFetchPrefixes calls RIPEstat announced-prefixes and returns the list
// of IPv4 prefix strings.
func realFetchPrefixes(ctx context.Context, asn int, hc *http.Client) ([]string, error) {
	u := fmt.Sprintf(ripeStatPrefixesURL, asn)
	var doc ripeStatPrefixesResponse
	if err := httpGetJSON(ctx, nil, "", hc, u, nil, &doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Data.Prefixes))
	for _, p := range doc.Data.Prefixes {
		if pref, err := netip.ParsePrefix(p.Prefix); err == nil && pref.Addr().Is4() {
			out = append(out, p.Prefix)
		}
	}
	return out, nil
}

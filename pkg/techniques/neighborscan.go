package techniques

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(neighborScanTechnique{}) }

// neighborScanTechnique mirrors unwaf's --scan-neighbors behavior: once an
// origin has been actively confirmed, expand that IPv4 to its /24 and probe
// nearby web hosts with the same host-header validation used elsewhere.
//
// Tier: Active. This is deliberately a confirmed-candidate consumer so it runs
// only after host_header/asn_sweep have proven at least one origin. That keeps
// the default behavior useful without turning weak passive guesses into /24
// scans.
type neighborScanTechnique struct{}

func (neighborScanTechnique) Name() string                      { return "neighbor_scan" }
func (neighborScanTechnique) Tier() Tier                        { return TierActive }
func (neighborScanTechnique) RequiresAPIKey() bool              { return false }
func (neighborScanTechnique) DefaultWeight() float64            { return 0.78 }
func (neighborScanTechnique) ConsumesConfirmedCandidates() bool { return true }
func (neighborScanTechnique) TimeoutOverride() time.Duration    { return 4 * time.Minute }

const neighborScanWorkers = 64

func (neighborScanTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if len(opts.SeedIPs) == 0 {
		return nil, nil
	}
	targetHost := canonicalTargetHost(target)
	neighbors := expandConfirmedNeighbors(opts.SeedIPs)
	if len(neighbors) == 0 {
		return nil, nil
	}

	base, err := fetchBaseline(ctx, targetHost, newHostHeaderBaselineClient())
	if err != nil {
		return nil, fmt.Errorf("neighbor_scan baseline: %w", err)
	}
	direct := newHostHeaderDirectClient()
	insecure := newHostHeaderInsecureClient(targetHost)

	in := make(chan netip.Addr, neighborScanWorkers)
	out := make(chan Candidate, neighborScanWorkers)

	var wg sync.WaitGroup
	for i := 0; i < neighborScanWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range in {
				cand, matched, _ := probeIPForHost(ctx, direct, insecure, ip, targetHost, base)
				if !matched {
					continue
				}
				annotateNeighborValidation(&cand)
				cand.Evidence = fmt.Sprintf("neighbor_scan: /24 neighbor of confirmed origin - %s", cand.Evidence)
				select {
				case out <- cand:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, ip := range neighbors {
			select {
			case in <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()

	seen := map[netip.Addr]bool{}
	var cands []Candidate
	for cand := range out {
		ip, err := netip.ParseAddr(cand.IP)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		cands = append(cands, cand)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].IP < cands[j].IP })
	cands = append(cands, neighborScanDiagnostic(fmt.Sprintf(
		"scanned %d neighboring IPv4 address(es) across %d confirmed /24 seed(s); confirmed %d neighbor(s)",
		len(neighbors), countNeighborSubnets(opts.SeedIPs), len(cands),
	)))
	return cands, nil
}

func expandConfirmedNeighbors(seeds []netip.Addr) []netip.Addr {
	seedSet := map[netip.Addr]bool{}
	subnets := map[[3]byte]bool{}
	for _, seed := range seeds {
		seed = seed.Unmap()
		if !seed.Is4() || isReservedAddr(seed) || cdn.IsCDNIP(seed) {
			continue
		}
		b := seed.As4()
		seedSet[seed] = true
		subnets[[3]byte{b[0], b[1], b[2]}] = true
	}
	if len(subnets) == 0 {
		return nil
	}

	var out []netip.Addr
	for subnet := range subnets {
		for host := byte(1); host < 255; host++ {
			ip := netip.AddrFrom4([4]byte{subnet[0], subnet[1], subnet[2], host})
			if seedSet[ip] || isReservedAddr(ip) || cdn.IsCDNIP(ip) {
				continue
			}
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func annotateNeighborValidation(c *Candidate) {
	if c.Metadata == nil {
		c.Metadata = map[string]any{}
	}
	raw, ok := c.Metadata["validation"].(map[string]any)
	if !ok {
		return
	}
	raw["technique"] = "neighbor_scan"
	if method, _ := raw["method"].(string); method != "" {
		raw["method"] = method + "_neighbor"
		return
	}
	raw["method"] = "neighbor"
}

func countNeighborSubnets(seeds []netip.Addr) int {
	subnets := map[[3]byte]bool{}
	for _, seed := range seeds {
		seed = seed.Unmap()
		if !seed.Is4() || isReservedAddr(seed) || cdn.IsCDNIP(seed) {
			continue
		}
		b := seed.As4()
		subnets[[3]byte{b[0], b[1], b[2]}] = true
	}
	return len(subnets)
}

func neighborScanDiagnostic(message string) Candidate {
	return Candidate{Metadata: map[string]any{
		"diagnostic": map[string]any{
			"event":   "summary",
			"message": message,
		},
	}}
}

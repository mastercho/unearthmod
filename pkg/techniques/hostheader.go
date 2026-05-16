package techniques

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/internal/httpclient"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(hostHeaderTechnique{}) }

// hostHeaderTechnique validates candidate origin IPs by connecting to each
// candidate by address and requesting the target's site with the Host
// header set to the target domain. A direct-IP response that mirrors the
// target's content and is missing the CDN's identifying headers is a
// strong confirmation that this IP is the real origin.
//
// Tier: Active. Per Packet 5A §6, this is a phase-2 consumer technique:
// it pulls candidate IPs from RunOptions.SeedIPs (populated by the engine
// from phase-1 producers) rather than discovering its own.
//
// Cache: not cached. The technique is doing real-time validation; a
// cached "this IP serves the site" can become wrong fast.
type hostHeaderTechnique struct{}

func (hostHeaderTechnique) Name() string             { return "host_header" }
func (hostHeaderTechnique) Tier() Tier               { return TierActive }
func (hostHeaderTechnique) RequiresAPIKey() bool     { return false }
func (hostHeaderTechnique) DefaultWeight() float64   { return 0.85 }
func (hostHeaderTechnique) ConsumesCandidates() bool { return true }

const (
	hostHeaderWorkers       = 8
	hostHeaderPerProbeLimit = 8 * 1024 // bytes read from each probe body
)

// newHostHeaderInsecureClient builds the dedicated TLS-skip client used
// for direct-IP probes. Exposed as a package var so tests can inject a
// stub client whose transport is the test's RoundTripper, sharing the
// fixture set with the baseline call. Production code path is unchanged.
var newHostHeaderInsecureClient = func() *http.Client {
	return httpclient.New(httpclient.Options{
		Timeout:     10 * time.Second,
		InsecureTLS: true,
	})
}

func (hostHeaderTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if len(opts.SeedIPs) == 0 {
		return nil, nil // nothing to validate
	}

	// Build a baseline of what the target's normal front door looks like:
	// status, length, body hash, and the headers we'll filter out.
	base, err := fetchBaseline(ctx, target, opts.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("host_header baseline: %w", err)
	}

	// Build a dedicated client that skips TLS verification, since
	// connecting by IP will mismatch the certificate's name. This is the
	// one place §5.1 explicitly permits a per-technique client — and it
	// still goes through httpclient.New so timeouts and user-agent stay
	// consistent with the rest of the tool.
	insecure := newHostHeaderInsecureClient()

	type result struct {
		ip       netip.Addr
		evidence string
		ok       bool
	}
	in := make(chan netip.Addr)
	out := make(chan result)

	var wg sync.WaitGroup
	for i := 0; i < hostHeaderWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range in {
				if cdn.IsCDNIP(ip) {
					continue
				}
				evidence, matched := probeIPForHost(ctx, insecure, ip, target, base)
				if !matched {
					continue
				}
				select {
				case out <- result{ip: ip, evidence: evidence, ok: true}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, ip := range opts.SeedIPs {
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
	for r := range out {
		if seen[r.ip] {
			continue
		}
		seen[r.ip] = true
		cands = append(cands, Candidate{IP: r.ip.String(), Evidence: r.evidence})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].IP < cands[j].IP })
	return cands, nil
}

// baseline captures what the target's normal front door returns. We use
// it as the "this looks like the site" reference for direct-IP probes.
type baseline struct {
	status   int
	bodyHash string
	bodyLen  int
}

func fetchBaseline(ctx context.Context, target string, hc *http.Client) (baseline, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+target+"/", nil)
	if err != nil {
		return baseline{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return baseline{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, hostHeaderPerProbeLimit))
	sum := sha256.Sum256(body)
	return baseline{
		status:   resp.StatusCode,
		bodyHash: hex.EncodeToString(sum[:]),
		bodyLen:  len(body),
	}, nil
}

// probeIPForHost performs the actual direct-IP request and decides
// whether the response confirms ip is serving target's site.
func probeIPForHost(ctx context.Context, hc *http.Client, ip netip.Addr, target string, base baseline) (string, bool) {
	host := ip.String()
	if ip.Is6() {
		host = "[" + host + "]"
	}
	url := "https://" + host + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	req.Host = target
	resp, err := hc.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()

	// Reject if response carries CDN markers — that means we hit the CDN,
	// not the origin.
	if hasCDNHeaders(resp.Header) {
		return "", false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, hostHeaderPerProbeLimit))
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])

	// Strong match: same status, same body. Likely the real origin.
	if resp.StatusCode == base.status && bodyHash == base.bodyHash {
		return fmt.Sprintf("host_header: %s served %s with status %d and matching body hash (no CDN headers)",
			ip, target, resp.StatusCode), true
	}
	// Looser match: same status and body length within 5% of baseline,
	// when baseline is non-trivial. Origins commonly insert/strip a
	// small marker but otherwise serve identical content.
	if resp.StatusCode == base.status && base.bodyLen > 256 {
		diff := base.bodyLen - len(body)
		if diff < 0 {
			diff = -diff
		}
		if diff*20 < base.bodyLen {
			return fmt.Sprintf("host_header: %s served %s with status %d and body length within 5%% of baseline",
				ip, target, resp.StatusCode), true
		}
	}
	return "", false
}

func hasCDNHeaders(h http.Header) bool {
	if strings.EqualFold(h.Get("Server"), "cloudflare") {
		return true
	}
	for _, k := range []string{"Cf-Ray", "X-Amz-Cf-Id"} {
		if h.Get(k) != "" {
			return true
		}
	}
	via := strings.ToLower(h.Get("Via"))
	xc := strings.ToLower(h.Get("X-Cache"))
	return strings.Contains(via, "cloudfront") || strings.Contains(xc, "cloudfront")
}

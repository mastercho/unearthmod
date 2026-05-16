// Package cdn detects which CDN, if any, fronts a target and decides whether
// a given IP address belongs to a known CDN range. Both jobs are needed by
// the engine and by individual techniques: the engine surfaces CDN-fronting
// status to the caller; techniques drop candidates that are still inside a
// CDN, because they cannot be the real origin.
//
// CDN coverage in v1.0: Cloudflare and CloudFront. The code is structured so
// adding Akamai, Fastly, or Sucuri later is a matter of dropping in a
// Provider value with detection markers and an embedded range snapshot —
// not a rewrite.
package cdn

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// SnapshotDate records when the embedded Cloudflare and CloudFront range
// data was captured. Refresh callers can compare against this to decide
// whether to fetch fresh ranges.
const SnapshotDate = "2026-05-16"

//go:embed data/cloudflare-v4.txt
var cloudflareV4Raw []byte

//go:embed data/cloudflare-v6.txt
var cloudflareV6Raw []byte

//go:embed data/cloudfront.json
var cloudfrontRaw []byte

// Provider describes one known CDN: its canonical name, the DNS / HTTP
// signals that identify it, and the IP prefixes it owns.
type Provider struct {
	Name     string
	dnsHints []string // suffixes (case-insensitive) checked against CNAME / NS
	prefixes []netip.Prefix
}

// Indirections used by Detect so tests can stub DNS without faking
// net.DefaultResolver. Production code points at net.DefaultResolver.
var (
	detectLookupCNAME  = net.DefaultResolver.LookupCNAME
	detectLookupNS     = net.DefaultResolver.LookupNS
	detectLookupIPAddr = net.DefaultResolver.LookupIPAddr
)

// providers is the in-process registry of every CDN we know about. The
// slice order matters for tie-breaking in ProviderForIP (first match wins),
// but Cloudflare and CloudFront ranges don't overlap.
var providers []*Provider

func init() {
	cf, err := buildCloudflare()
	if err != nil {
		// Embedded data is part of the binary; a parse failure here is a
		// build-time bug, not a runtime condition.
		panic(fmt.Sprintf("cdn: parsing embedded Cloudflare ranges: %v", err))
	}
	providers = append(providers, cf)

	cfront, err := buildCloudFront()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded CloudFront ranges: %v", err))
	}
	providers = append(providers, cfront)
}

func buildCloudflare() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(cloudflareV4Raw)
	if err != nil {
		return nil, fmt.Errorf("cloudflare v4: %w", err)
	}
	v6, err := parsePlainPrefixes(cloudflareV6Raw)
	if err != nil {
		return nil, fmt.Errorf("cloudflare v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name:     "cloudflare",
		dnsHints: []string{".cloudflare.net", ".cloudflare.com", ".ns.cloudflare.com"},
		prefixes: prefixes,
	}, nil
}

func buildCloudFront() (*Provider, error) {
	type rawIPv4 struct {
		IPPrefix string `json:"ip_prefix"`
		Service  string `json:"service"`
	}
	type rawIPv6 struct {
		IPv6Prefix string `json:"ipv6_prefix"`
		Service    string `json:"service"`
	}
	var raw struct {
		Prefixes     []rawIPv4 `json:"prefixes"`
		IPv6Prefixes []rawIPv6 `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(cloudfrontRaw, &raw); err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, p := range raw.Prefixes {
		if p.Service != "CLOUDFRONT" {
			continue
		}
		pref, err := netip.ParsePrefix(p.IPPrefix)
		if err != nil {
			return nil, fmt.Errorf("ipv4 prefix %q: %w", p.IPPrefix, err)
		}
		prefixes = append(prefixes, pref)
	}
	for _, p := range raw.IPv6Prefixes {
		if p.Service != "CLOUDFRONT" {
			continue
		}
		pref, err := netip.ParsePrefix(p.IPv6Prefix)
		if err != nil {
			return nil, fmt.Errorf("ipv6 prefix %q: %w", p.IPv6Prefix, err)
		}
		prefixes = append(prefixes, pref)
	}
	return &Provider{
		Name:     "cloudfront",
		dnsHints: []string{".cloudfront.net"},
		prefixes: prefixes,
	}, nil
}

func parsePlainPrefixes(b []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %q: %w", line, err)
		}
		out = append(out, p)
	}
	return out, s.Err()
}

// IsCDNIP reports whether ip is owned by any known CDN provider.
func IsCDNIP(ip netip.Addr) bool {
	return ProviderForIP(ip) != ""
}

// ProviderForIP returns the canonical CDN name that owns ip, or "" when no
// known provider claims it. RFC1918, loopback, and similarly private
// addresses are simply not in any provider's list and therefore yield "".
func ProviderForIP(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	for _, p := range providers {
		for _, pref := range p.prefixes {
			if pref.Contains(ip) {
				return p.Name
			}
		}
	}
	return ""
}

// Detection is the result of CDN fingerprinting for one target.
type Detection struct {
	// CDN is the canonical provider name ("" when no CDN is detected).
	CDN string
	// Signals lists every matched detection rule, suitable for evidence
	// strings or debug logging.
	Signals []string
}

// Detect determines which CDN, if any, fronts target. It uses three signal
// sources: DNS (CNAME chain and NS records), HTTP response headers from one
// GET to https://target/, and the target's resolved A/AAAA records compared
// against embedded CDN range tables.
//
// At most one HTTP request is made to the target. That is the standard way
// to fingerprint a CDN — a normal browser visit produces the same request —
// and is documented as the only target-touching action in this otherwise
// fully passive layer.
//
// A nil hc is treated as http.DefaultClient. A non-nil hc lets the engine
// share its tuned client across techniques and the CDN detector.
//
// Detect returns the first detection it finds plus every signal that
// matched, so callers can present rich evidence. Errors from DNS or HTTP
// are non-fatal in spirit — the function still returns a usable Detection
// reflecting whatever signals did match — but the underlying error, if any,
// is also returned so the caller can surface it as a warning.
func Detect(ctx context.Context, target string, hc *http.Client) (Detection, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	det := Detection{}
	var firstErr error
	captureErr := func(err error) {
		if err == nil || firstErr != nil {
			return
		}
		firstErr = err
	}
	setCDN := func(name, signal string) {
		if det.CDN == "" {
			det.CDN = name
		}
		det.Signals = append(det.Signals, signal)
	}

	// 1) DNS CNAME chain.
	if cname, err := detectLookupCNAME(ctx, target); err == nil {
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname != "" && cname != strings.ToLower(target) {
			if p, hit := providerByDNS(cname); hit {
				setCDN(p, fmt.Sprintf("CNAME %s matches %s", cname, p))
			}
		}
	} else {
		captureErr(err)
	}

	// 2) NS records.
	if nss, err := detectLookupNS(ctx, target); err == nil {
		for _, ns := range nss {
			host := strings.TrimSuffix(strings.ToLower(ns.Host), ".")
			if p, hit := providerByDNS(host); hit {
				setCDN(p, fmt.Sprintf("NS %s matches %s", host, p))
				break
			}
		}
	} else {
		captureErr(err)
	}

	// 3) A/AAAA → IP range.
	if ipAddrs, err := detectLookupIPAddr(ctx, target); err == nil {
		for _, ia := range ipAddrs {
			a, ok := netip.AddrFromSlice(ia.IP)
			if !ok {
				continue
			}
			a = a.Unmap()
			if p := ProviderForIP(a); p != "" {
				setCDN(p, fmt.Sprintf("A/AAAA %s in %s range", a, p))
				break
			}
		}
	} else {
		captureErr(err)
	}

	// 4) One HTTP request for header inspection.
	if hdrCDN, signals, err := headerProbe(ctx, target, hc); err == nil {
		for _, s := range signals {
			setCDN(hdrCDN, s)
		}
	} else {
		captureErr(err)
	}

	return det, firstErr
}

func providerByDNS(host string) (string, bool) {
	host = strings.ToLower(host)
	for _, p := range providers {
		for _, hint := range p.dnsHints {
			if strings.HasSuffix(host, hint) {
				return p.Name, true
			}
		}
	}
	return "", false
}

func headerProbe(ctx context.Context, target string, hc *http.Client) (string, []string, error) {
	url := "https://" + target + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	return classifyHeaders(resp.Header), collectHeaderSignals(resp.Header), nil
}

// classifyHeaders chooses the most likely CDN from response headers. If both
// Cloudflare and CloudFront markers appear (rare; usually means a chained
// setup), Cloudflare wins because its markers — server: cloudflare + cf-ray
// — are stronger and harder to fake than CloudFront's.
func classifyHeaders(h http.Header) string {
	if strings.EqualFold(h.Get("Server"), "cloudflare") || h.Get("Cf-Ray") != "" {
		return "cloudflare"
	}
	if h.Get("X-Amz-Cf-Id") != "" {
		return "cloudfront"
	}
	// Looser CloudFront markers: x-cache / via with CloudFront token.
	if strings.Contains(strings.ToLower(h.Get("Via")), "cloudfront") {
		return "cloudfront"
	}
	if strings.Contains(strings.ToLower(h.Get("X-Cache")), "cloudfront") {
		return "cloudfront"
	}
	return ""
}

func collectHeaderSignals(h http.Header) []string {
	var out []string
	if strings.EqualFold(h.Get("Server"), "cloudflare") {
		out = append(out, "header server: cloudflare")
	}
	if h.Get("Cf-Ray") != "" {
		out = append(out, "header cf-ray present")
	}
	if h.Get("X-Amz-Cf-Id") != "" {
		out = append(out, "header x-amz-cf-id present")
	}
	if via := strings.ToLower(h.Get("Via")); strings.Contains(via, "cloudfront") {
		out = append(out, "header via mentions cloudfront")
	}
	if xc := strings.ToLower(h.Get("X-Cache")); strings.Contains(xc, "cloudfront") {
		out = append(out, "header x-cache mentions cloudfront")
	}
	return out
}

// Refresh fetches fresh range data from Cloudflare and AWS and rebuilds the
// in-memory provider tables. The default sources are the same URLs the
// embedded snapshot was captured from; tests pass custom URLs.
//
// Refresh is safe to call at any time but is not goroutine-safe with
// concurrent IsCDNIP/ProviderForIP calls — callers serialize it themselves.
// The CLI will expose this as `unearth cdn refresh` in a later packet.
func Refresh(ctx context.Context, hc *http.Client) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	v4, err := fetch(ctx, hc, "https://www.cloudflare.com/ips-v4")
	if err != nil {
		return fmt.Errorf("cdn refresh cloudflare v4: %w", err)
	}
	v6, err := fetch(ctx, hc, "https://www.cloudflare.com/ips-v6")
	if err != nil {
		return fmt.Errorf("cdn refresh cloudflare v6: %w", err)
	}
	aws, err := fetch(ctx, hc, "https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return fmt.Errorf("cdn refresh cloudfront: %w", err)
	}

	cfPrefixes, err := parsePlainPrefixes(v4)
	if err != nil {
		return err
	}
	cfV6, err := parsePlainPrefixes(v6)
	if err != nil {
		return err
	}
	cfPrefixes = append(cfPrefixes, cfV6...)

	// Reuse the build helper for CloudFront, swapping its source bytes.
	prev := cloudfrontRaw
	cloudfrontRaw = aws
	cfront, err := buildCloudFront()
	cloudfrontRaw = prev
	if err != nil {
		return err
	}

	newProviders := []*Provider{
		{Name: "cloudflare", dnsHints: providers[0].dnsHints, prefixes: cfPrefixes},
		cfront,
	}
	providers = newProviders
	return nil
}

func fetch(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	buf := bytes.NewBuffer(nil)
	const maxRefresh = 16 << 20 // 16 MiB cap
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, resp.Body, maxRefresh)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

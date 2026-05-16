// File ctfingerprint.go implements the ct_fingerprint passive technique:
// the keyless cert→origin pivot. Two backends run in parallel, results
// merge by IP within the technique, and a single-backend failure does
// not fail the run — only both backends down returns an error.
//
// Backend A — kaeferjaeger.gay sni-ip-ranges
//   Plain-text per-provider scans of cloud-provider IPv4 space: each
//   non-empty line is "IP:PORT -- [SAN1 SAN2 SAN3 ...]". Five files,
//   one per provider (amazon, digitalocean, google, microsoft, oracle),
//   total ~640 MB. We stream-download to disk, cache for 24h, and
//   stream-scan line by line — never load a whole file into memory.
//
// Backend B — SSLMate Cert Spotter v1 (keyless tier)
//   GET https://api.certspotter.com/v1/issuances?domain=<target>
//       &include_subdomains=true&expand=dns_names
//   Returns a coalesced-by-tbs_sha256 JSON array of issuances, each
//   with dns_names[]. We extract IP-literal SANs directly, resolve
//   hostnames, and emit non-CDN IPs. The keyless tier is ~75/hour;
//   one call per target is plenty.

package techniques

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(ctFingerprintTechnique{}) }

type ctFingerprintTechnique struct{}

func (ctFingerprintTechnique) Name() string           { return "ct_fingerprint" }
func (ctFingerprintTechnique) Tier() Tier             { return TierPassive }
func (ctFingerprintTechnique) RequiresAPIKey() bool   { return false }
func (ctFingerprintTechnique) DefaultWeight() float64 { return 0.70 }

// TimeoutOverride widens the per-technique budget for ct_fingerprint.
// On a cold cache the technique streams up to ~640 MB of provider data
// from kaeferjaeger.gay, which can take a couple of minutes on modest
// connections. 120 s is enough for the warm case and for the cold case
// when only some provider downloads complete before the deadline — the
// engine and the technique's own backend-degradation logic both keep
// partial results.
func (ctFingerprintTechnique) TimeoutOverride() time.Duration { return 2 * time.Minute }

const (
	ctFingerprintTTL = 6 * time.Hour

	kaeferjaegerBase     = "https://kaeferjaeger.gay/sni-ip-ranges"
	kaeferjaegerDataFile = "ipv4_merged_sni.txt"
	kaeferjaegerMaxAge   = 24 * time.Hour
	certSpotterURL       = "https://api.certspotter.com/v1/issuances"
)

// kaeferjaegerProviders is the set of provider directories we mirror.
// Order is stable so test runs and evidence strings are reproducible.
var kaeferjaegerProviders = []string{"amazon", "digitalocean", "google", "microsoft", "oracle"}

// datasetFetcher abstracts dataset retrieval so tests inject fixture
// files instead of streaming from kaeferjaeger.gay.
type datasetFetcher interface {
	// Open returns a ReadCloser of the named provider's dataset bytes.
	// Implementations are responsible for caching to disk and honoring
	// the refresh flag.
	Open(ctx context.Context, provider string, refresh bool) (io.ReadCloser, string, error)
}

// activeKaeferjaegerFetcher is the package-level fetcher used in
// production; tests swap it via setKaeferjaegerFetcher.
var activeKaeferjaegerFetcher datasetFetcher = &httpKaeferjaegerFetcher{}

func setKaeferjaegerFetcher(f datasetFetcher) datasetFetcher {
	prev := activeKaeferjaegerFetcher
	activeKaeferjaegerFetcher = f
	return prev
}

func (ctFingerprintTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	key := cache.Key("ct_fingerprint", target, nil)
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		var items []Candidate
		if err := json.Unmarshal(cached, &items); err == nil {
			return items, nil
		}
	}

	type backendResult struct {
		name  string
		cands []Candidate
		err   error
	}
	results := make(chan backendResult, 2)

	go func() {
		c, err := runKaeferjaegerBackend(ctx, target, opts)
		results <- backendResult{name: "kaeferjaeger", cands: c, err: err}
	}()
	go func() {
		c, err := runCertSpotterBackend(ctx, target, opts)
		results <- backendResult{name: "ct", cands: c, err: err}
	}()

	merged := map[string]*Candidate{}
	var failedBackends, succeededBackends []string
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil {
			failedBackends = append(failedBackends, fmt.Sprintf("%s: %v", r.name, r.err))
			continue
		}
		succeededBackends = append(succeededBackends, r.name)
		for _, c := range r.cands {
			if existing, ok := merged[c.IP]; ok {
				// Same IP from both backends — fold evidence so the
				// reader sees both attestations under one entry.
				existing.Evidence = existing.Evidence + " | " + c.Evidence
				continue
			}
			cc := c
			merged[c.IP] = &cc
		}
	}

	// §4.4: only both-backends-down returns an error.
	if len(succeededBackends) == 0 {
		return nil, fmt.Errorf("ct_fingerprint: all backends failed: %s",
			strings.Join(failedBackends, "; "))
	}

	out := make([]Candidate, 0, len(merged))
	for _, c := range merged {
		out = append(out, *c)
	}
	// If one backend failed, the surviving evidence carries a note so
	// the user sees the partial-result attribution without us logging.
	if len(failedBackends) > 0 && len(out) > 0 {
		note := " | note: partial result, " + strings.Join(failedBackends, "; ")
		for i := range out {
			out[i].Evidence += note
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	if payload, err := json.Marshal(out); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, ctFingerprintTTL)
	}
	return out, nil
}

// --- Backend A: kaeferjaeger ---------------------------------------------

func runKaeferjaegerBackend(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return nil, errors.New("empty target")
	}

	type providerResult struct {
		name  string
		cands []Candidate
		err   error
	}
	ch := make(chan providerResult, len(kaeferjaegerProviders))
	var wg sync.WaitGroup
	for _, p := range kaeferjaegerProviders {
		wg.Add(1)
		go func(provider string) {
			defer wg.Done()
			if err := rateWait(ctx, opts.RateLimiter, "kaeferjaeger"); err != nil {
				ch <- providerResult{name: provider, err: err}
				return
			}
			rc, datasetDate, err := activeKaeferjaegerFetcher.Open(ctx, provider, opts.Refresh)
			if err != nil {
				ch <- providerResult{name: provider, err: err}
				return
			}
			defer func() { _ = rc.Close() }()
			cands, err := scanKaeferjaegerDataset(ctx, rc, target, provider, datasetDate)
			ch <- providerResult{name: provider, cands: cands, err: err}
		}(p)
	}
	go func() { wg.Wait(); close(ch) }()

	seen := map[netip.Addr]bool{}
	var out []Candidate
	var failures []string
	var successes int
	for r := range ch {
		if r.err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", r.name, r.err))
			continue
		}
		successes++
		for _, c := range r.cands {
			a, err := netip.ParseAddr(c.IP)
			if err != nil || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, c)
		}
	}
	if successes == 0 {
		return nil, fmt.Errorf("kaeferjaeger: no provider files available: %s",
			strings.Join(failures, "; "))
	}
	return out, nil
}

// scanKaeferjaegerDataset streams the dataset line by line, emitting a
// Candidate for every line whose SAN list names target (exact or
// wildcard) and whose IP is outside known CDN ranges.
func scanKaeferjaegerDataset(ctx context.Context, r io.Reader, target, provider, datasetDate string) ([]Candidate, error) {
	scn := bufio.NewScanner(r)
	scn.Buffer(make([]byte, 0, 64*1024), 1024*1024) // line cap = 1 MiB
	var out []Candidate
	for scn.Scan() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		ip, sans, ok := parseKaeferjaegerLine(scn.Text())
		if !ok {
			continue
		}
		if !sansNameTarget(sans, target) {
			continue
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if cdn.IsCDNIP(a) {
			continue
		}
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"ct_fingerprint/kaeferjaeger: %s serves a cert for %s (%s SNI scan, dataset %s)",
				a, target, provider, datasetDate),
		})
	}
	return out, scn.Err()
}

// parseKaeferjaegerLine parses one line of the form
//
//	1.178.10.3:443 -- [s3vectors.eu-central-1.api.aws *.s3vectors.eu-central-1.vpce.amazonaws.com]
//
// It returns the IP (stripped of port) and the list of SANs.
func parseKaeferjaegerLine(line string) (string, []string, bool) {
	// IP:port and SAN block are separated by " -- ". Anything else
	// (HTML, empty, comments) gets skipped.
	const sep = " -- "
	i := strings.Index(line, sep)
	if i < 0 {
		return "", nil, false
	}
	left := line[:i]
	right := strings.TrimSpace(line[i+len(sep):])
	if !strings.HasPrefix(right, "[") || !strings.HasSuffix(right, "]") {
		return "", nil, false
	}
	// Strip the colon-port: IP is everything before the last ':'.
	if j := strings.LastIndex(left, ":"); j > 0 {
		left = left[:j]
	}
	sans := strings.Fields(right[1 : len(right)-1])
	if len(sans) == 0 {
		return "", nil, false
	}
	return left, sans, true
}

func sansNameTarget(sans []string, target string) bool {
	target = strings.ToLower(target)
	for _, s := range sans {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == target {
			return true
		}
		if strings.HasPrefix(s, "*.") && s[2:] == target {
			return true
		}
		// A wildcard for the parent zone also covers our target.
		if strings.HasPrefix(s, "*.") && strings.HasSuffix(target, "."+s[2:]) {
			return true
		}
	}
	return false
}

// httpKaeferjaegerFetcher is the production implementation: HTTPS
// streaming download with a 24h on-disk cache under XDG_CACHE_HOME.
type httpKaeferjaegerFetcher struct{}

func (f *httpKaeferjaegerFetcher) Open(ctx context.Context, provider string, refresh bool) (io.ReadCloser, string, error) {
	dir, err := datasetCacheDir()
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, provider+"_"+kaeferjaegerDataFile)
	info, statErr := os.Stat(path)
	stale := refresh || statErr != nil || time.Since(info.ModTime()) > kaeferjaegerMaxAge

	if stale {
		if err := downloadKaeferjaeger(ctx, provider, path); err != nil {
			// If a stale download fails but a previous file exists,
			// fall through and use the stale copy — better than nothing.
			if statErr != nil {
				return nil, "", err
			}
		}
	}

	info, err = os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	rc, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	return rc, info.ModTime().UTC().Format("2006-01-02"), nil
}

func downloadKaeferjaeger(ctx context.Context, provider, dest string) error {
	url := fmt.Sprintf("%s/%s/%s", kaeferjaegerBase, provider, kaeferjaegerDataFile)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("kaeferjaeger %s: status %d", provider, resp.StatusCode)
	}
	tmp := dest + ".tmp"
	f, err := os.Create(tmp) // #nosec G304
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func datasetCacheDir() (string, error) {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "unearth", "datasets"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "unearth", "datasets"), nil
}

// --- Backend B: Cert Spotter -------------------------------------------

type certSpotterIssuance struct {
	CertSHA256 string   `json:"cert_sha256"`
	DNSNames   []string `json:"dns_names"`
}

func runCertSpotterBackend(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if err := rateWait(ctx, opts.RateLimiter, "ct"); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s?domain=%s&include_subdomains=true&expand=dns_names",
		certSpotterURL, target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certspotter: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("certspotter: status %d", resp.StatusCode)
	}
	var doc []certSpotterIssuance
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("certspotter decode: %w", err)
	}

	// 1) Direct IP-literal SANs (rare but real).
	// 2) Hostnames → resolve → non-CDN IPs.
	seen := map[netip.Addr]string{} // IP -> cert fingerprint that surfaced it
	addHit := func(a netip.Addr, fp string) {
		a = a.Unmap()
		if !a.IsValid() || cdn.IsCDNIP(a) {
			return
		}
		if _, dup := seen[a]; dup {
			return
		}
		seen[a] = fp
	}
	for _, iss := range doc {
		fp := iss.CertSHA256
		for _, name := range iss.DNSNames {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if a, err := netip.ParseAddr(name); err == nil {
				addHit(a, fp)
				continue
			}
			if strings.HasPrefix(name, "*.") {
				continue // wildcard SAN has no resolvable form on its own
			}
			if err := rateWait(ctx, opts.RateLimiter, "dns"); err != nil {
				continue
			}
			addrs, err := activeResolver.LookupAddrs(ctx, name)
			if err != nil {
				continue
			}
			for _, a := range addrs {
				addHit(a, fp)
			}
		}
	}
	out := make([]Candidate, 0, len(seen))
	for a, fp := range seen {
		fpShort := fp
		if len(fpShort) > 16 {
			fpShort = fpShort[:16] + "…"
		}
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"ct_fingerprint/ct: %s via certificate %s naming %s (Cert Spotter)",
				a, fpShort, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

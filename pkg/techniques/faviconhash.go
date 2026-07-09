package techniques

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
	"golang.org/x/net/html"
)

func init() { Register(faviconHashTechnique{}) }

// faviconHashTechnique fetches the target's declared favicon, computes its
// MurmurHash3 the way Shodan, Censys, FOFA and ZoomEye do — mmh3 over the
// standard-base64 encoding of the raw favicon bytes — then asks Shodan
// (http.favicon.hash:<hash>) and/or Censys
// (services.http.response.favicons.hashes) for every other host presenting
// that same favicon. Hosts outside known CDN ranges are origin candidates:
// CDN edge nodes rarely serve the same application favicon as the origin
// they front, so a favicon match elsewhere usually exposes the real origin.
//
// The favicon hash is stable across IP moves and cert rotations, so it
// complements the cert-pivot techniques (shodan_cert / censys_cert): a host
// that rotated its TLS cert is missed by cert pivots but caught here.
//
// Tier: Active. One outbound GET to the target page plus favicon touches the
// search-engine queries themselves are passive third-party lookups.
//
// Either backend alone is sufficient. With neither API key configured the
// technique skips gracefully (ErrMissingAPIKey), exactly like shodan_cert
// and censys_cert.
//
// SHODAN: /shodan/host/search with the http.favicon.hash filter, auth via
// ?key=<API_KEY>. CENSYS: the Platform global-search endpoint with the
// services.http.response.favicons.hashes field. Both endpoints are reused
// from the existing cert techniques' conventions.
const (
	faviconShodanField  = "http.favicon.hash"
	faviconCensysField  = "host.services.http.response.favicons.hashes"
	faviconHashTTL      = 1 * time.Hour
	faviconBodyLimit    = 4 * 1024 * 1024 // 4 MiB — favicons are tiny; cap defends against a hostile body.
	faviconFetchTimeout = 8 * time.Second
	faviconMaxIcons     = 8
)

type faviconHashTechnique struct{}

func (faviconHashTechnique) Name() string           { return "favicon_hash" }
func (faviconHashTechnique) Tier() Tier             { return TierActive }
func (faviconHashTechnique) RequiresAPIKey() bool   { return true }
func (faviconHashTechnique) DefaultWeight() float64 { return 0.75 }

type fetchedFavicon struct {
	Body []byte
	URL  string
}

// fetchFavicons is a package var so tests can stub the favicon fetch without
// standing up a real HTTP server for the target. It returns the raw favicon
// bytes, or an error when the favicon cannot be retrieved (404, network
// failure on both schemes, etc.).
var fetchFavicons = realFetchFavicons

func (faviconHashTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	haveShodan := opts.APIKeys.ShodanAPIKey != ""
	haveCensys := opts.APIKeys.CensysPlatformPAT != ""
	if !haveShodan && !haveCensys {
		return nil, ErrMissingAPIKey
	}

	favicons, err := fetchFavicons(ctx, target, newFaviconFetchClient())
	if err != nil {
		return nil, fmt.Errorf("favicon_hash fetch: %w", err)
	}
	if len(favicons) == 0 {
		// No favicon body — nothing to hash, no candidates. Not an error:
		// many sites legitimately lack a favicon.
		return []Candidate{faviconDiagnosticCandidate("no favicon body fetched; Shodan/Censys favicon search was not queried")}, nil
	}

	seen := map[netip.Addr]bool{}
	seenHashes := map[int32]bool{}
	var out []Candidate
	var backendErrs []error
	successes := 0

	for _, fav := range favicons {
		hash := faviconMMH3(fav.Body)
		if seenHashes[hash] {
			continue
		}
		seenHashes[hash] = true
		out = append(out, faviconDiagnosticCandidate(fmt.Sprintf("fetched favicon url=%s bytes=%d mmh3:%d", fav.URL, len(fav.Body), hash)))

		if haveShodan {
			cands, err := faviconShodanQuery(ctx, target, hash, opts)
			if err != nil {
				backendErrs = append(backendErrs, err)
				out = append(out, faviconDiagnosticCandidate(fmt.Sprintf("Shodan favicon search failed for mmh3:%d: %v", hash, err)))
			} else {
				successes++
				out = append(out, faviconDiagnosticCandidate(fmt.Sprintf("Shodan favicon search produced %d non-CDN candidate(s) for mmh3:%d", len(cands), hash)))
				out = appendFaviconCandidates(out, seen, cands)
			}
		}
		if haveCensys {
			cands, err := faviconCensysQuery(ctx, target, hash, opts)
			if err != nil {
				backendErrs = append(backendErrs, err)
				out = append(out, faviconDiagnosticCandidate(fmt.Sprintf("Censys favicon search failed for mmh3:%d: %v", hash, err)))
			} else {
				successes++
				out = append(out, faviconDiagnosticCandidate(fmt.Sprintf("Censys favicon search produced %d non-CDN candidate(s) for mmh3:%d", len(cands), hash)))
				out = appendFaviconCandidates(out, seen, cands)
			}
		}
	}
	if successes == 0 && len(backendErrs) > 0 {
		return nil, errors.Join(backendErrs...)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

var newFaviconFetchClient = func() *http.Client {
	return newHostHeaderBrowserClient(faviconFetchTimeout, "")
}

// faviconMMH3 computes the favicon hash exactly as Shodan does: base64-encode
// the raw bytes with line wrapping at 76 columns and a trailing newline
// (Python's base64.encodebytes), then take the signed 32-bit MurmurHash3 of
// that base64 text. Shodan, Censys, FOFA and ZoomEye all key on this value.
func faviconMMH3(raw []byte) int32 {
	b64 := base64EncodeWrapped(raw)
	return int32(murmurHash3X86_32([]byte(b64), 0))
}

// murmurHash3X86_32 is a self-contained, allocation-free implementation of
// MurmurHash3's x86_32 variant — the exact algorithm Shodan, Censys, FOFA and
// ZoomEye use to index favicons. It replaces github.com/spaolacci/murmur3,
// whose v1.1.0 release performs unsafe pointer arithmetic that trips Go's
// -race / checkptr instrumentation ("pointer arithmetic result points to
// invalid allocation") and kept CI red (prob-unearth-murmur3-race-001).
//
// This version reads the input with encoding/binary-style byte assembly only,
// so it is pointer-safe and produces byte-for-byte identical hashes. The
// locked TestFaviconHash_MMH3Convention value (-384845062) guards that
// equivalence against any future regression.
func murmurHash3X86_32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)

	h := seed
	nblocks := len(data) / 4

	// Body: process 4-byte little-endian blocks.
	for i := 0; i < nblocks; i++ {
		b := data[i*4:]
		k := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24

		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2

		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}

	// Tail: remaining 1-3 bytes.
	var k uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}

	// Finalization.
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16

	return h
}

// base64EncodeWrapped mirrors Python's base64.encodebytes: standard base64,
// a newline inserted every 76 output characters, and a trailing newline.
// Matching this layout byte-for-byte is mandatory — the mmh3 hash is taken
// over the wrapped text, so any deviation produces a different (wrong) hash
// that will never match Shodan's index.
func base64EncodeWrapped(raw []byte) string {
	enc := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}

func appendFaviconCandidates(out []Candidate, seen map[netip.Addr]bool, cands []Candidate) []Candidate {
	for _, c := range cands {
		a, err := netip.ParseAddr(c.IP)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, c)
	}
	return out
}

// realFetchFavicon resolves the same kind of favicon source Shodan usually
// indexes: first icon links declared by the page HTML, then /favicon.ico.
// It falls back from HTTPS to HTTP and treats reachable non-2xx icon URLs as
// "no favicon" rather than a hard error.
func realFetchFavicon(ctx context.Context, target string, hc *http.Client) ([]byte, error) {
	favicons, err := realFetchFavicons(ctx, target, hc)
	if err != nil || len(favicons) == 0 {
		return nil, err
	}
	return favicons[0].Body, nil
}

func realFetchFavicons(ctx context.Context, target string, hc *http.Client) ([]fetchedFavicon, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	var sawResponse bool
	var lastErr error
	seenURL := map[string]bool{}
	seenHash := map[int32]bool{}
	var out []fetchedFavicon
	for _, scheme := range []string{"https", "http"} {
		pageURL := scheme + "://" + target + "/"
		baseURL, _ := url.Parse(pageURL)
		var iconURLs []string
		if body, finalURL, ok, err := faviconPage(ctx, pageURL, hc); err != nil {
			lastErr = err
		} else if ok {
			sawResponse = true
			if finalURL != nil {
				baseURL = finalURL
			}
			iconURLs = append(iconURLs, faviconIconURLs(body, baseURL)...)
		}
		iconURLs = appendUniqueURL(iconURLs, resolveFaviconURL(baseURL, "/favicon.ico"))
		for _, iconURL := range iconURLs {
			if seenURL[iconURL] {
				continue
			}
			seenURL[iconURL] = true
			raw, ok, err := faviconGet(ctx, iconURL, hc)
			if err != nil {
				lastErr = err
				continue
			}
			sawResponse = true
			if ok && len(raw) > 0 {
				hash := faviconMMH3(raw)
				if seenHash[hash] {
					continue
				}
				seenHash[hash] = true
				out = append(out, fetchedFavicon{Body: raw, URL: iconURL})
				if len(out) >= faviconMaxIcons {
					return out, nil
				}
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if sawResponse {
		return nil, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("favicon_hash: could not fetch favicon for %s over https or http: %w", target, lastErr)
	}
	return nil, fmt.Errorf("favicon_hash: could not fetch favicon for %s over https or http", target)
}

// faviconGet performs a single GET. ok reports whether the server returned a
// favicon body (2xx). A non-2xx status returns ok=false with a nil error so
// the caller can distinguish "no favicon" from "transport failed".
func faviconGet(ctx context.Context, rawURL string, hc *http.Client) (body []byte, ok bool, err error) {
	return faviconGET(ctx, rawURL, hc, "image/x-icon,image/vnd.microsoft.icon,image/*,*/*")
}

func faviconPage(ctx context.Context, rawURL string, hc *http.Client) (body string, finalURL *url.URL, ok bool, err error) {
	b, ok, err := faviconGET(ctx, rawURL, hc, "text/html,application/xhtml+xml")
	if err != nil || !ok {
		return "", nil, ok, err
	}
	u, _ := url.Parse(rawURL)
	return string(b), u, true, nil
}

func faviconGET(ctx context.Context, rawURL string, hc *http.Client, accept string) (body []byte, ok bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", accept)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, false, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, faviconBodyLimit))
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func faviconIconURLs(raw string, base *url.URL) []string {
	doc, err := html.Parse(strings.NewReader(raw))
	if err != nil {
		return nil
	}
	var out []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "link") {
			var rel, href string
			for _, a := range n.Attr {
				switch strings.ToLower(a.Key) {
				case "rel":
					rel = a.Val
				case "href":
					href = a.Val
				}
			}
			if faviconRel(rel) {
				out = appendUniqueURL(out, resolveFaviconURL(base, href))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func faviconRel(rel string) bool {
	for _, field := range strings.Fields(strings.ToLower(rel)) {
		if strings.Contains(field, "icon") {
			return true
		}
	}
	return false
}

func resolveFaviconURL(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(strings.ToLower(href), "data:") || base == nil {
		return ""
	}
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func appendUniqueURL(urls []string, next string) []string {
	if next == "" {
		return urls
	}
	for _, existing := range urls {
		if existing == next {
			return urls
		}
	}
	return append(urls, next)
}

// --- Shodan query path ---

func faviconShodanQuery(ctx context.Context, target string, hash int32, opts RunOptions) ([]Candidate, error) {
	key := cache.Key("favicon_hash", target, map[string]string{"hash": fmt.Sprintf("%d", hash), "backend": "shodan", "schema": "v2"})
	var cached shodanSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return faviconShodanCandidates(cached, target, hash), nil
		}
	}

	var merged shodanSearchResponse
	page := 1
	for {
		if opts.Budget != nil && !opts.Budget.Charge("shodan") {
			return nil, ErrBudgetExhausted
		}
		if err := rateWait(ctx, opts.RateLimiter, "shodan"); err != nil {
			return nil, err
		}
		got, err := faviconShodanPage(ctx, opts, hash, page)
		if err != nil {
			return nil, err
		}
		merged.Matches = append(merged.Matches, got.Matches...)
		merged.Total = got.Total
		if len(got.Matches) == 0 || len(merged.Matches) >= got.Total {
			break
		}
		page++
	}
	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, faviconHashTTL)
	}
	return faviconShodanCandidates(merged, target, hash), nil
}

func faviconShodanPage(ctx context.Context, opts RunOptions, hash int32, page int) (shodanSearchResponse, error) {
	var doc shodanSearchResponse
	q := url.Values{}
	q.Set("key", opts.APIKeys.ShodanAPIKey)
	q.Set("query", fmt.Sprintf("%s:%d", faviconShodanField, hash))
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
		return doc, fmt.Errorf("favicon_hash shodan: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("favicon_hash shodan: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden {
		return doc, fmt.Errorf("favicon_hash shodan: status 403: %w", ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("favicon_hash shodan: %s status %d", shodanSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("favicon_hash shodan decode: %w", err)
	}
	if doc.Error != "" {
		if isShodanTierError(doc.Error) {
			return doc, fmt.Errorf("favicon_hash shodan: %s: %w", doc.Error, ErrTierInsufficient)
		}
		return doc, fmt.Errorf("favicon_hash shodan: %s", doc.Error)
	}
	return doc, nil
}

func faviconShodanCandidates(doc shodanSearchResponse, target string, hash int32) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, m := range doc.Matches {
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
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"Shodan: host %s serves favicon mmh3:%d also presented by %s",
				a, hash, target),
		})
	}
	return out
}

func faviconDiagnosticCandidate(message string) Candidate {
	return Candidate{
		Metadata: map[string]any{
			"diagnostic": map[string]any{
				"event":   "info",
				"message": message,
			},
		},
	}
}

// --- Censys query path ---

func faviconCensysQuery(ctx context.Context, target string, hash int32, opts RunOptions) ([]Candidate, error) {
	key := cache.Key("favicon_hash", target, map[string]string{"hash": fmt.Sprintf("%d", hash), "backend": "censys"})
	var cached censysSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return faviconCensysCandidates(cached, target, hash), nil
		}
	}

	var merged censysSearchResponse
	pageToken := ""
	for {
		if opts.Budget != nil && !opts.Budget.Charge("censys") {
			return nil, ErrBudgetExhausted
		}
		if err := rateWait(ctx, opts.RateLimiter, "censys"); err != nil {
			return nil, err
		}
		page, err := faviconCensysPage(ctx, opts, hash, pageToken)
		if err != nil {
			return nil, err
		}
		merged.Result.Hits = append(merged.Result.Hits, page.Result.Hits...)
		if page.Result.NextPageToken == "" {
			break
		}
		pageToken = page.Result.NextPageToken
	}
	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, faviconHashTTL)
	}
	return faviconCensysCandidates(merged, target, hash), nil
}

func faviconCensysPage(ctx context.Context, opts RunOptions, hash int32, pageToken string) (censysSearchResponse, error) {
	var doc censysSearchResponse
	body, err := json.Marshal(censysSearchRequest{
		Query:     fmt.Sprintf(`%s=%d`, faviconCensysField, hash),
		Fields:    []string{"host.ip"},
		PageSize:  censysSearchPageSize,
		PageToken: pageToken,
	})
	if err != nil {
		return doc, fmt.Errorf("favicon_hash censys encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, censysPlatformSearchURL, strings.NewReader(string(body)))
	if err != nil {
		return doc, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.APIKeys.CensysPlatformPAT)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("favicon_hash censys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return doc, fmt.Errorf("favicon_hash censys: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("favicon_hash censys: %s status %d", censysPlatformSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("favicon_hash censys decode: %w", err)
	}
	return doc, nil
}

func faviconCensysCandidates(doc censysSearchResponse, target string, hash int32) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, h := range doc.Result.Hits {
		a, err := netip.ParseAddr(h.Host.IP)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if seen[a] || cdn.IsCDNIP(a) {
			continue
		}
		seen[a] = true
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"Censys: host %s serves favicon mmh3:%d also presented by %s",
				a, hash, target),
		})
	}
	return out
}

package techniques

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 — required by Shodan's ssl.cert.fingerprint filter, not used for security
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(censysCertTechnique{}) }

// censysCertTechnique fetches the target's current TLS leaf-certificate
// fingerprint, then asks the Censys Platform API for every host that
// presents the same fingerprint. A host outside known CDN ranges is a
// strong origin candidate — CDNs typically serve their own certs, so a
// match elsewhere usually means the origin is misconfigured to serve its
// real cert directly.
//
// CENSYS PLATFORM API endpoint — isolated in one constant per spec.
// Targeting the Free-tier-callable global search endpoint
// (POST /v3/global/search/query) on the Censys Platform API. The
// alternative threat-hunting "certificate observations" endpoint is paid-
// only (Adversary Investigation module) and is therefore unsuitable for a
// tool that promises a usable Free tier.
//
// CenQL field used for the lookup: `host.services.cert.fingerprint_sha256`.
// (The Platform schema collapsed leaf-cert metadata under
// `services.cert.*`; the older `services.tls.certificates.leaf_fp_sha_256`
// form does not exist on Platform.)
const (
	censysPlatformSearchURL = "https://api.platform.censys.io/v3/global/search/query"
	censysFingerprintField  = "host.services.cert.fingerprint_sha256"
	censysSearchPageSize    = 100
)

const censysCertTTL = 1 * time.Hour

type censysCertTechnique struct{}

func (censysCertTechnique) Name() string           { return "censys_cert" }
func (censysCertTechnique) Tier() Tier             { return TierPassive }
func (censysCertTechnique) RequiresAPIKey() bool   { return true }
func (censysCertTechnique) DefaultWeight() float64 { return 0.90 }

// censysSearchRequest is the JSON body shape the Platform search endpoint
// expects. Only the fields we need are populated.
type censysSearchRequest struct {
	Query     string   `json:"query"`
	Fields    []string `json:"fields,omitempty"`
	PageSize  int      `json:"page_size,omitempty"`
	PageToken string   `json:"page_token,omitempty"`
}

// censysSearchResponse is the subset of the Platform search payload we
// read. The response envelope is {"result": {...}}.
type censysSearchResponse struct {
	Result struct {
		Hits []struct {
			Host struct {
				IP string `json:"ip"`
			} `json:"host"`
		} `json:"hits"`
		NextPageToken string `json:"next_page_token"`
	} `json:"result"`
}

// tlsFingerprint is a function var so tests can stub it without standing
// up a real TLS server. It returns the SHA-256 of the target's leaf
// certificate as lowercase hex.
var tlsFingerprint = realTLSFingerprint

// tlsFingerprintSHA1 returns the SHA-1 of the target's leaf certificate as
// lowercase hex. Shodan's `ssl.cert.fingerprint` filter uses SHA-1 (unlike
// Censys, which uses SHA-256), so shodan_cert needs this sibling. A
// package var, like tlsFingerprint, so tests can stub it.
var tlsFingerprintSHA1 = realTLSFingerprintSHA1

func (censysCertTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.CensysPlatformPAT == "" {
		return nil, ErrMissingAPIKey
	}

	// 1) fingerprint the target's current leaf cert.
	fp, err := tlsFingerprint(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("censys_cert fingerprint: %w", err)
	}

	// 2) cache check before charging the budget.
	key := cache.Key("censys_cert", target, map[string]string{"fp": fp, "api": "platform"})
	var cached censysSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return censysCandidates(cached, target, fp), nil
		}
	}

	// 3) live call. Charge the Censys budget before each page so a
	// misconfigured loop cannot drain the user's credits.
	var merged censysSearchResponse
	pageToken := ""
	for {
		if opts.Budget != nil && !opts.Budget.Charge("censys") {
			return nil, ErrBudgetExhausted
		}
		if err := rateWait(ctx, opts.RateLimiter, "censys"); err != nil {
			return nil, err
		}
		page, err := censysSearchPage(ctx, opts, fp, pageToken)
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
		cacheWrite(opts.Cache, opts, key, payload, censysCertTTL)
	}
	return censysCandidates(merged, target, fp), nil
}

func censysSearchPage(ctx context.Context, opts RunOptions, fp, pageToken string) (censysSearchResponse, error) {
	var doc censysSearchResponse
	body, err := json.Marshal(censysSearchRequest{
		Query:     fmt.Sprintf(`%s="%s"`, censysFingerprintField, fp),
		Fields:    []string{"host.ip"},
		PageSize:  censysSearchPageSize,
		PageToken: pageToken,
	})
	if err != nil {
		return doc, fmt.Errorf("censys_cert encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, censysPlatformSearchURL, bytes.NewReader(body))
	if err != nil {
		return doc, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.APIKeys.CensysPlatformPAT)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("censys_cert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// 401/403 from the Platform search endpoint almost always means
		// the PAT is valid but the account tier lacks the host-search
		// capability (Free tier may not include it). Surface this as a
		// tier_insufficient skip rather than a scary error.
		return doc, fmt.Errorf("censys_cert: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("censys_cert: %s status %d", censysPlatformSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("censys_cert decode: %w", err)
	}
	return doc, nil
}

func censysCandidates(doc censysSearchResponse, target, fp string) []Candidate {
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
				"Censys: host %s serves cert sha256:%s also presented by %s",
				a, fp, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func realTLSFingerprint(ctx context.Context, target string) (string, error) {
	raw, err := leafCertDER(ctx, target)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func realTLSFingerprintSHA1(ctx context.Context, target string) (string, error) {
	raw, err := leafCertDER(ctx, target)
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(raw) // #nosec G401 — Shodan requires SHA-1 for ssl.cert.fingerprint
	return hex.EncodeToString(sum[:]), nil
}

// leafCertDER dials the target on :443 and returns the raw DER bytes of
// its leaf certificate, so both fingerprint hash flavors share one dial.
func leafCertDER(ctx context.Context, target string) ([]byte, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: target,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target, "443"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("tls handshake did not return *tls.Conn")
	}
	chain := tc.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("peer presented no certificates")
	}
	return chain[0].Raw, nil
}

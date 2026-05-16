package techniques

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(censysCertTechnique{}) }

// censysCertTechnique fetches the target's current TLS certificate
// fingerprint, then asks Censys to list every host serving that
// fingerprint. Any reported host outside known CDN ranges is a strong
// origin candidate — the CDN typically presents its own cert, so a hit on
// the target's leaf cert at a different IP almost always means the origin
// is misconfigured to serve the same cert.
//
// CENSYS API ENDPOINT — isolated in one constant per Packet 3 §6.5.
// Targeting Censys legacy Search API v2, which still operates as of the
// snapshot date but is documented as deprecated; migration to the Platform
// v3 API (api.platform.censys.io, Bearer PAT auth) is tracked separately
// — see the Packet 3 report-back §10 for context.
const censysSearchV2Hosts = "https://search.censys.io/api/v2/hosts/search"

const censysCertTTL = 1 * time.Hour

type censysCertTechnique struct{}

func (censysCertTechnique) Name() string           { return "censys_cert" }
func (censysCertTechnique) Tier() Tier             { return TierPassive }
func (censysCertTechnique) RequiresAPIKey() bool   { return true }
func (censysCertTechnique) DefaultWeight() float64 { return 0.90 }

// censysHostsSearchResponse is the subset of the v2 hosts/search payload we
// need.
type censysHostsSearchResponse struct {
	Result struct {
		Hits []struct {
			IP string `json:"ip"`
		} `json:"hits"`
	} `json:"result"`
}

// tlsFingerprint is a function var so tests can stub it without standing up
// a real TLS server.
var tlsFingerprint = realTLSFingerprint

func (censysCertTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.CensysAPIID == "" || opts.APIKeys.CensysAPISecret == "" {
		return nil, ErrMissingAPIKey
	}

	// 1) fingerprint the target's current leaf cert.
	fp, err := tlsFingerprint(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("censys_cert fingerprint: %w", err)
	}

	// 2) check cache before charging the budget.
	key := cache.Key("censys_cert", target, map[string]string{"fp": fp})
	var doc censysHostsSearchResponse
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		if err := json.Unmarshal(cached, &doc); err == nil && len(doc.Result.Hits) >= 0 {
			return censysCandidates(doc, target, fp), nil
		}
	}

	// 3) live call — costs one Censys credit. Charge the budget first.
	if opts.Budget != nil && !opts.Budget.Charge("censys") {
		return nil, ErrBudgetExhausted
	}

	if err := rateWait(ctx, opts.RateLimiter, "censys"); err != nil {
		return nil, err
	}
	q := fmt.Sprintf("services.tls.certificates.leaf_data.fingerprint:%s", fp)
	u := censysSearchV2Hosts + "?q=" + url.QueryEscape(q) + "&per_page=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(opts.APIKeys.CensysAPIID, opts.APIKeys.CensysAPISecret)
	req.Header.Set("Accept", "application/json")
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("censys_cert: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("censys_cert: %s status %d", censysSearchV2Hosts, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("censys_cert decode: %w", err)
	}
	if payload, err := json.Marshal(doc); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, censysCertTTL)
	}
	return censysCandidates(doc, target, fp), nil
}

func censysCandidates(doc censysHostsSearchResponse, target, fp string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, h := range doc.Result.Hits {
		a, err := netip.ParseAddr(h.IP)
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
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: target,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target, "443"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "", errors.New("tls handshake did not return *tls.Conn")
	}
	chain := tc.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return "", errors.New("peer presented no certificates")
	}
	sum := sha256.Sum256(chain[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

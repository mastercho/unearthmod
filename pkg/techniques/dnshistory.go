package techniques

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(dnsHistoryTechnique{}) }

// dnsHistoryTechnique queries third-party services for historical A records
// of the target. SecurityTrails is preferred (richer history); ViewDNS is
// the fallback when only its key is set. Either way the technique skips
// itself entirely when no key is available.
type dnsHistoryTechnique struct{}

const dnsHistoryTTL = 6 * time.Hour

func (dnsHistoryTechnique) Name() string           { return "dns_history" }
func (dnsHistoryTechnique) Tier() Tier             { return TierPassive }
func (dnsHistoryTechnique) RequiresAPIKey() bool   { return true }
func (dnsHistoryTechnique) DefaultWeight() float64 { return 0.65 }

func (dnsHistoryTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	switch {
	case opts.APIKeys.SecurityTrailsKey != "":
		return runSecurityTrails(ctx, target, opts)
	case opts.APIKeys.ViewDNSKey != "":
		return runViewDNS(ctx, target, opts)
	default:
		return nil, ErrMissingAPIKey
	}
}

// --- SecurityTrails -----------------------------------------------------

type stHistoryResponse struct {
	Records []struct {
		Values []struct {
			IP string `json:"ip"`
		} `json:"values"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
	} `json:"records"`
}

func runSecurityTrails(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	key := cache.Key("dns_history", target, map[string]string{"src": "securitytrails"})
	var doc stHistoryResponse
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		if err := json.Unmarshal(cached, &doc); err != nil {
			doc = stHistoryResponse{}
		}
	}
	if len(doc.Records) == 0 {
		url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", target)
		decorate := func(r *http.Request) { r.Header.Set("APIKEY", opts.APIKeys.SecurityTrailsKey) }
		if err := httpGetJSON(ctx, opts.RateLimiter, "securitytrails", opts.HTTPClient, url, decorate, &doc); err != nil {
			return nil, fmt.Errorf("securitytrails: %w", err)
		}
		payload, _ := json.Marshal(doc)
		cacheWrite(opts.Cache, opts, key, payload, dnsHistoryTTL)
	}
	type ipObs struct {
		first, last string
	}
	byIP := map[netip.Addr]ipObs{}
	for _, rec := range doc.Records {
		for _, v := range rec.Values {
			a, err := netip.ParseAddr(v.IP)
			if err != nil {
				continue
			}
			a = a.Unmap()
			if cdn.IsCDNIP(a) {
				continue
			}
			obs := byIP[a]
			if obs.first == "" || (rec.FirstSeen != "" && rec.FirstSeen < obs.first) {
				obs.first = rec.FirstSeen
			}
			if rec.LastSeen > obs.last {
				obs.last = rec.LastSeen
			}
			byIP[a] = obs
		}
	}
	out := make([]Candidate, 0, len(byIP))
	for a, obs := range byIP {
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"historical A record %s, observed %s–%s (SecurityTrails)",
				a, fallback(obs.first, "?"), fallback(obs.last, "?")),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

// --- ViewDNS ------------------------------------------------------------

type viewDNSResponse struct {
	Response struct {
		Records []struct {
			IP       string `json:"ip"`
			LastSeen string `json:"lastseen"`
		} `json:"records"`
	} `json:"response"`
}

func runViewDNS(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	key := cache.Key("dns_history", target, map[string]string{"src": "viewdns"})
	var doc viewDNSResponse
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		if err := json.Unmarshal(cached, &doc); err != nil {
			doc = viewDNSResponse{}
		}
	}
	if len(doc.Response.Records) == 0 {
		url := fmt.Sprintf(
			"https://api.viewdns.info/iphistory/?domain=%s&apikey=%s&output=json",
			target, opts.APIKeys.ViewDNSKey,
		)
		if err := httpGetJSON(ctx, opts.RateLimiter, "viewdns", opts.HTTPClient, url, nil, &doc); err != nil {
			return nil, fmt.Errorf("viewdns: %w", err)
		}
		payload, _ := json.Marshal(doc)
		cacheWrite(opts.Cache, opts, key, payload, dnsHistoryTTL)
	}
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, rec := range doc.Response.Records {
		a, err := netip.ParseAddr(rec.IP)
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
				"historical A record %s, last seen %s (ViewDNS)",
				a, fallback(rec.LastSeen, "?")),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

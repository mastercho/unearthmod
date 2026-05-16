package techniques

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(subdomainTechnique{}) }

//go:embed wordlist.txt
var subdomainWordlistRaw []byte

const subdomainTTL = 12 * time.Hour
const subdomainWorkers = 10

type subdomainTechnique struct{}

func (subdomainTechnique) Name() string           { return "subdomain_enum" }
func (subdomainTechnique) Tier() Tier             { return TierPassive }
func (subdomainTechnique) RequiresAPIKey() bool   { return false }
func (subdomainTechnique) DefaultWeight() float64 { return 0.35 }

func (subdomainTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	key := cache.Key("subdomain_enum", target, nil)
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		var items []Candidate
		if err := json.Unmarshal(cached, &items); err == nil {
			return items, nil
		}
	}

	prefixes := subdomainPrefixes()
	type result struct {
		prefix string
		addrs  []netip.Addr
		err    error
	}
	in := make(chan string)
	results := make(chan result)

	var wg sync.WaitGroup
	for i := 0; i < subdomainWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for prefix := range in {
				if err := rateWait(ctx, opts.RateLimiter, "dns"); err != nil {
					results <- result{prefix: prefix, err: err}
					continue
				}
				host := prefix + "." + target
				addrs, err := activeResolver.LookupAddrs(ctx, host)
				select {
				case results <- result{prefix: prefix, addrs: addrs, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, p := range prefixes {
			select {
			case in <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	seen := map[netip.Addr]bool{}
	var out []Candidate
	for r := range results {
		if r.err != nil {
			continue
		}
		host := r.prefix + "." + target
		for _, a := range r.addrs {
			a = a.Unmap()
			if !a.IsValid() || seen[a] || cdn.IsCDNIP(a) {
				continue
			}
			seen[a] = true
			out = append(out, Candidate{
				IP:       a.String(),
				Evidence: fmt.Sprintf("subdomain %s resolves to non-CDN %s", host, a),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	if payload, err := json.Marshal(out); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, subdomainTTL)
	}
	return out, nil
}

func subdomainPrefixes() []string {
	var out []string
	s := bufio.NewScanner(bytes.NewReader(subdomainWordlistRaw))
	for s.Scan() {
		p := strings.TrimSpace(s.Text())
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		out = append(out, p)
	}
	return out
}

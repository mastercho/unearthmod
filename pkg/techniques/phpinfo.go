package techniques

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(phpInfoTechnique{}) }

// phpInfoTechnique probes the public phpinfo endpoints from ProjectDiscovery's
// Nuclei phpinfo-files template, then extracts the origin address exposed in
// server-side phpinfo variables such as SERVER_ADDR and LOCAL_ADDR.
type phpInfoTechnique struct{}

func (phpInfoTechnique) Name() string           { return "phpinfo_scan" }
func (phpInfoTechnique) Tier() Tier             { return TierAggressive }
func (phpInfoTechnique) RequiresAPIKey() bool   { return false }
func (phpInfoTechnique) DefaultWeight() float64 { return 0.74 }

const (
	phpInfoBodyLimit    = 256 * 1024
	phpInfoProbeTimeout = 3 * time.Second
	phpInfoWorkers      = 8
)

var (
	phpInfoTagPattern   = regexp.MustCompile(`(?s)<[^>]+>`)
	phpInfoLabelPattern = regexp.MustCompile(`\b(?:SERVER_ADDR|LOCAL_ADDR)\b`)
)

var phpInfoPaths = []string{
	"/php.php",
	"/php2.php",
	"/phpinfo.php",
	"/info.php",
	"/infophp.php",
	"/php_info.php",
	"/test.php",
	"/i.php",
	"/a.php",
	"/p.php",
	"/pi.php",
	"/asdf.php",
	"/pinfo.php",
	"/phpversion.php",
	"/time.php",
	"/inf0.php",
	"/index.php",
	"/temp.php",
	"/old_phpinfo.php",
	"/infos.php",
	"/linusadmin-phpinfo.php",
	"/php-info.php",
	"/dashboard/phpinfo.php",
	"/_profiler/phpinfo.php",
	"/_profiler/phpinfo",
	"/?phpinfo=1",
	"/l.php?act=phpinfo",
	"/testxx.php",
}

func (phpInfoTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	hc := opts.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var urls []string
	for _, baseURL := range phpInfoBaseURLs(target) {
		for _, path := range phpInfoPaths {
			urls = append(urls, baseURL+path)
		}
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		url  string
		body string
	}
	jobs := make(chan string)
	results := make(chan result, 1)
	var wg sync.WaitGroup
	for i := 0; i < phpInfoWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				if err := rateWait(scanCtx, opts.RateLimiter, "phpinfo"); err != nil {
					return
				}
				body, ok := fetchPHPInfo(scanCtx, hc, u)
				if !ok {
					continue
				}
				select {
				case results <- result{url: u, body: body}:
					cancel()
				case <-scanCtx.Done():
				}
				return
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, u := range urls {
			select {
			case jobs <- u:
			case <-scanCtx.Done():
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case r := <-results:
		<-done
		return phpInfoCandidates(r.body, r.url), nil
	case <-done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func phpInfoBaseURLs(target string) []string {
	t := strings.TrimRight(strings.TrimSpace(target), "/")
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return []string{t}
	}
	return []string{"https://" + t, "http://" + t}
}

func fetchPHPInfo(ctx context.Context, hc *http.Client, u string) (string, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, phpInfoProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := hc.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, phpInfoBodyLimit))
	if err != nil {
		return "", false
	}
	text := string(body)
	if !strings.Contains(text, "PHP Extension") || !strings.Contains(text, "PHP Version") {
		return "", false
	}
	return text, true
}

func phpInfoCandidates(body, sourceURL string) []Candidate {
	seen := map[netip.Addr]string{}
	for label, a := range extractPHPInfoIPs(body) {
		if !a.IsValid() || isUnroutable(a) || cdn.IsCDNIP(a) {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = label
	}

	out := make([]Candidate, 0, len(seen))
	for a, label := range seen {
		out = append(out, Candidate{
			IP:       a.String(),
			Evidence: fmt.Sprintf("phpinfo_scan: %s exposed %s at %s", label, a, sourceURL),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func extractPHPInfoIPs(body string) map[string]netip.Addr {
	text := phpInfoText(body)
	out := map[string]netip.Addr{}
	for _, loc := range phpInfoLabelPattern.FindAllStringIndex(text, -1) {
		label := text[loc[0]:loc[1]]
		end := loc[1] + 160
		if end > len(text) {
			end = len(text)
		}
		if a, ok := firstIPToken(text[loc[1]:end]); ok {
			out[label] = a
		}
	}
	return out
}

func phpInfoText(body string) string {
	text := html.UnescapeString(body)
	text = phpInfoTagPattern.ReplaceAllString(text, " ")
	return strings.Join(strings.Fields(text), " ")
}

func firstIPToken(text string) (netip.Addr, bool) {
	for _, tok := range strings.Fields(text) {
		raw := strings.Trim(tok, `"'[](),;`)
		a, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

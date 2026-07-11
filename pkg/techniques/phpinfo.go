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
	phpInfoBodyLimit    = 2 * 1024 * 1024
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

var newPHPInfoChallengeClient = func() *http.Client {
	return newHostHeaderBrowserClient(phpInfoProbeTimeout, "")
}

func (phpInfoTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	hc := opts.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	challengeClient := newPHPInfoChallengeClient()

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
	var challengeOnce sync.Once
	var challengeURL string
	var wg sync.WaitGroup
	for i := 0; i < phpInfoWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				if err := rateWait(scanCtx, opts.RateLimiter, "phpinfo"); err != nil {
					return
				}
				body, ok, challenged := fetchPHPInfo(scanCtx, hc, challengeClient, u)
				if !ok {
					if challenged {
						challengeOnce.Do(func() { challengeURL = u })
					}
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
		// A successful worker sends its result before decrementing the wait
		// group. If both channels become ready together, prefer that buffered
		// result instead of incorrectly reporting a zero-result scan.
		select {
		case r := <-results:
			return phpInfoCandidates(r.body, r.url), nil
		default:
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if challengeURL != "" {
			return []Candidate{phpInfoDiagnosticCandidate(fmt.Sprintf(
				"Cloudflare challenge blocked phpinfo inspection at %s; the endpoint may be visible in a browser but its SERVER_ADDR was not present in the scanner response",
				challengeURL,
			))}, nil
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

func fetchPHPInfo(ctx context.Context, hc, challengeClient *http.Client, u string) (string, bool, bool) {
	body, ok, challenged := fetchPHPInfoOnce(ctx, hc, u)
	if ok || !challenged || challengeClient == nil || challengeClient == hc {
		return body, ok, challenged
	}
	body, ok, retryChallenged := fetchPHPInfoOnce(ctx, challengeClient, u)
	return body, ok, retryChallenged
}

func fetchPHPInfoOnce(ctx context.Context, hc *http.Client, u string) (string, bool, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, phpInfoProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, u, nil)
	if err != nil {
		return "", false, false
	}
	setHostHeaderBrowserHeaders(req)

	resp, err := hc.Do(req)
	if err != nil {
		return "", false, false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, phpInfoBodyLimit))
	if err != nil {
		return "", false, false
	}
	text := string(body)
	if resp.StatusCode != http.StatusOK {
		return "", false, isCloudflareChallenge(resp, text)
	}
	if !strings.Contains(text, "PHP Extension") || !strings.Contains(text, "PHP Version") {
		return "", false, false
	}
	return text, true, false
}

func isCloudflareChallenge(resp *http.Response, body string) bool {
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("Cf-Mitigated")), "challenge") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(resp.Header.Get("Server")), "cloudflare") &&
		(strings.Contains(strings.ToLower(body), "just a moment") ||
			strings.Contains(strings.ToLower(body), "challenges.cloudflare.com"))
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

func phpInfoDiagnosticCandidate(message string) Candidate {
	return Candidate{Metadata: map[string]any{
		"diagnostic": map[string]any{
			"event":   "blocked",
			"message": message,
		},
	}}
}

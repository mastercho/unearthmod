package techniques

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/pkg/cdn"
	"golang.org/x/net/html"
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
func (hostHeaderTechnique) TimeoutOverride() time.Duration {
	return 2 * time.Minute
}

const (
	hostHeaderWorkers             = 24
	hostHeaderPerProbeLimit       = 256 * 1024
	hostHeaderMinBodyTextLen      = 80
	hostHeaderConfirmThreshold    = 0.60
	hostHeaderProbeTimeout        = 3 * time.Second
	hostHeaderGenericErrorPenalty = 0.20
	hostHeaderMaxDiagnostics      = 5
)

type hostHeaderEndpoint struct {
	Scheme string
	Port   int
}

type hostHeaderProbeMode struct {
	Method string
	Host   string
}

type hostHeaderDiagnostic struct {
	Event       string
	Message     string
	IP          string
	Method      string
	URL         string
	StatusCode  int
	Reason      string
	Score       float64
	HTMLScore   float64
	CertScore   float64
	HeaderScore float64
}

var hostHeaderProbeEndpoints = []hostHeaderEndpoint{
	{Scheme: "https", Port: 443},
	{Scheme: "http", Port: 80},
	{Scheme: "http", Port: 8080},
	{Scheme: "https", Port: 8443},
}

var newHostHeaderBaselineClient = func() *http.Client {
	return newHostHeaderBrowserClient(hostHeaderProbeTimeout, "")
}

// newHostHeaderDirectClient builds the TLS-skip client for true direct-IP
// probes. It intentionally does not pin TLS ServerName to the target; this
// matches browser/direct-IP verification used by tools like unwaf.
var newHostHeaderDirectClient = func() *http.Client {
	return newHostHeaderProbeClient("")
}

// newHostHeaderInsecureClient builds the dedicated TLS-skip client used for
// host-header probes. The TLS ServerName is pinned to the target so HTTPS origins
// that route by SNI can be validated while connecting to an IP literal.
var newHostHeaderInsecureClient = func(target string) *http.Client {
	return newHostHeaderProbeClient(canonicalTargetHost(target))
}

func newHostHeaderProbeClient(serverNameOverride string) *http.Client {
	hc := newHostHeaderBrowserClient(hostHeaderProbeTimeout, serverNameOverride)
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return hc
}

func (hostHeaderTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if len(opts.SeedIPs) == 0 {
		return nil, nil // nothing to validate
	}

	targetHost := canonicalTargetHost(target)
	base, err := fetchBaseline(ctx, targetHost, newHostHeaderBaselineClient())
	if err != nil {
		return nil, fmt.Errorf("host_header baseline: %w", err)
	}

	direct := newHostHeaderDirectClient()
	insecure := newHostHeaderInsecureClient(targetHost)

	type result struct {
		candidate  Candidate
		diagnostic *hostHeaderDiagnostic
	}
	in := make(chan netip.Addr)
	out := make(chan result)

	var wg sync.WaitGroup
	for i := 0; i < hostHeaderWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range in {
				ip = ip.Unmap()
				if isInvalidHostHeaderSeed(ip) {
					continue
				}
				cand, matched, diagnostic := probeIPForHost(ctx, direct, insecure, ip, targetHost, base)
				if !matched {
					if diagnostic != nil {
						select {
						case out <- result{diagnostic: diagnostic}:
						case <-ctx.Done():
							return
						}
					}
					continue
				}
				select {
				case out <- result{candidate: cand}:
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
	diagnostics := []hostHeaderDiagnostic{hostHeaderBaselineDiagnostic(base)}
	for r := range out {
		if r.diagnostic != nil {
			diagnostics = append(diagnostics, *r.diagnostic)
			continue
		}
		ip, err := netip.ParseAddr(r.candidate.IP)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		cands = append(cands, r.candidate)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].IP < cands[j].IP })
	if len(cands) == 0 {
		for _, d := range topHostHeaderDiagnostics(diagnostics) {
			cands = append(cands, hostHeaderDiagnosticCandidate(d))
		}
	}
	return cands, nil
}

type baseline struct {
	URL     string
	Status  int
	Header  http.Header
	Body    string
	Text    string
	Title   string
	TLSCert *x509.Certificate
}

type hostHeaderProbe struct {
	URL     string
	Scheme  string
	Port    int
	Status  int
	Header  http.Header
	Body    string
	Text    string
	Title   string
	TLSCert *x509.Certificate
}

type hostHeaderScore struct {
	Overall float64
	HTML    float64
	Cert    float64
	Headers float64
	Title   bool
}

func fetchBaseline(ctx context.Context, target string, hc *http.Client) (baseline, error) {
	var firstErr error
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + target + "/"
		p, err := fetchHostHeaderResponse(ctx, hc, u, "")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return baseline{
			URL:     p.URL,
			Status:  p.Status,
			Header:  p.Header,
			Body:    p.Body,
			Text:    p.Text,
			Title:   p.Title,
			TLSCert: p.TLSCert,
		}, nil
	}
	return baseline{}, firstErr
}

func probeIPForHost(ctx context.Context, directClient, hostClient *http.Client, ip netip.Addr, target string, base baseline) (Candidate, bool, *hostHeaderDiagnostic) {
	var best Candidate
	var bestScore float64
	diagnostic := &hostHeaderDiagnostic{
		Event:   "reject",
		IP:      ip.String(),
		Reason:  "no_response",
		Message: "no HTTP/HTTPS probe response from candidate",
	}
	for _, ep := range hostHeaderProbeEndpoints {
		for _, mode := range []hostHeaderProbeMode{
			{Method: "direct"},
			{Method: "host_header", Host: target},
		} {
			hc := directClient
			if mode.Host != "" {
				hc = hostClient
			}
			p, err := fetchHostHeaderResponse(ctx, hc, hostHeaderProbeURL(ip, ep), mode.Host)
			if err != nil {
				continue
			}
			if !hostHeaderProbeURLMatchesIP(p.URL, ip) {
				diagnostic = betterHostHeaderDiagnostic(diagnostic, hostHeaderRejectDiagnostic(ip, mode.Method, p, hostHeaderScore{}, "redirected_off_candidate"))
				continue
			}
			if hasCDNHeaders(p.Header) {
				diagnostic = betterHostHeaderDiagnostic(diagnostic, hostHeaderRejectDiagnostic(ip, mode.Method, p, hostHeaderScore{}, "cdn_headers"))
				continue
			}
			if isGenericHostHeaderMatch(base.Status, p.Status) {
				diagnostic = betterHostHeaderDiagnostic(diagnostic, hostHeaderRejectDiagnostic(ip, mode.Method, p, hostHeaderScore{}, "generic_error_status"))
				continue
			}
			score := scoreHostHeaderProbe(base, p)
			if isWeakShortHostHeaderMatch(base, p, score) {
				diagnostic = betterHostHeaderDiagnostic(diagnostic, hostHeaderRejectDiagnostic(ip, mode.Method, p, score, "weak_short_body"))
				continue
			}
			if score.Overall < hostHeaderConfirmThreshold || score.Overall <= bestScore {
				diagnostic = betterHostHeaderDiagnostic(diagnostic, hostHeaderRejectDiagnostic(ip, mode.Method, p, score, "below_threshold"))
				continue
			}
			bestScore = score.Overall
			best = Candidate{
				IP:       ip.String(),
				Evidence: hostHeaderEvidence(ip, target, mode.Method, p, score),
				Metadata: map[string]any{
					"validation": map[string]any{
						"status":       "confirmed",
						"technique":    "host_header",
						"method":       mode.Method,
						"url":          p.URL,
						"scheme":       p.Scheme,
						"port":         p.Port,
						"status_code":  p.Status,
						"score":        roundScore(score.Overall),
						"html_score":   roundScore(score.HTML),
						"cert_score":   roundScore(score.Cert),
						"header_score": roundScore(score.Headers),
						"title_match":  score.Title,
						"threshold":    hostHeaderConfirmThreshold,
					},
				},
			}
		}
	}
	if best.IP != "" {
		return best, true, nil
	}
	return best, false, diagnostic
}

func hostHeaderProbeURLMatchesIP(rawURL string, want netip.Addr) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	got, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return false
	}
	return got.Unmap() == want.Unmap()
}

func fetchHostHeaderResponse(ctx context.Context, hc *http.Client, u, host string) (hostHeaderProbe, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return hostHeaderProbe{}, err
	}
	if host != "" {
		req.Host = host
	}
	setHostHeaderBrowserHeaders(req)
	resp, err := hc.Do(req)
	if err != nil {
		return hostHeaderProbe{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, hostHeaderPerProbeLimit))
	if err != nil {
		return hostHeaderProbe{}, err
	}
	text, title := normalizeHostHeaderHTML(string(body))
	probeURL := req.URL
	if resp.Request != nil && resp.Request.URL != nil {
		probeURL = resp.Request.URL
	}
	port := probeURL.Port()
	if port == "" {
		if probeURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	var cert *x509.Certificate
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert = resp.TLS.PeerCertificates[0]
	}
	return hostHeaderProbe{
		URL:     probeURL.String(),
		Scheme:  probeURL.Scheme,
		Port:    atoiDefault(port, 0),
		Status:  resp.StatusCode,
		Header:  resp.Header.Clone(),
		Body:    string(body),
		Text:    text,
		Title:   title,
		TLSCert: cert,
	}, nil
}

func scoreHostHeaderProbe(base baseline, p hostHeaderProbe) hostHeaderScore {
	htmlScore := textSimilarity(base.Text, p.Text)
	titleMatch := base.Title != "" && strings.EqualFold(base.Title, p.Title)
	if titleMatch && htmlScore < 0.75 {
		htmlScore = 0.75
	}
	certScore := certSimilarity(base.TLSCert, p.TLSCert)
	headerScore := compareHostHeaderHeaders(base.Header, p.Header)
	overall := 0.60*htmlScore + 0.25*certScore + 0.15*headerScore + statusAdjustment(base.Status, p.Status)
	if overall < 0 {
		overall = 0
	}
	if overall > 1 {
		overall = 1
	}
	return hostHeaderScore{
		Overall: overall,
		HTML:    htmlScore,
		Cert:    certScore,
		Headers: headerScore,
		Title:   titleMatch,
	}
}

func hostHeaderEvidence(ip netip.Addr, target, method string, p hostHeaderProbe, score hostHeaderScore) string {
	return fmt.Sprintf("host_header: %s confirmed %s via %s %s:%d status=%d score=%.2f html=%.2f cert=%.2f headers=%.2f",
		ip, target, method, p.Scheme, p.Port, p.Status, score.Overall, score.HTML, score.Cert, score.Headers)
}

func hostHeaderBaselineDiagnostic(base baseline) hostHeaderDiagnostic {
	return hostHeaderDiagnostic{
		Event:      "baseline",
		Message:    fmt.Sprintf("baseline fetched status=%d title=%q text_len=%d", base.Status, base.Title, len(base.Text)),
		URL:        base.URL,
		StatusCode: base.Status,
	}
}

func hostHeaderRejectDiagnostic(ip netip.Addr, method string, p hostHeaderProbe, score hostHeaderScore, reason string) *hostHeaderDiagnostic {
	return &hostHeaderDiagnostic{
		Event:       "reject",
		IP:          ip.String(),
		Method:      method,
		URL:         p.URL,
		StatusCode:  p.Status,
		Reason:      reason,
		Message:     fmt.Sprintf("best rejected probe score=%.2f reason=%s status=%d url=%s", score.Overall, reason, p.Status, p.URL),
		Score:       roundScore(score.Overall),
		HTMLScore:   roundScore(score.HTML),
		CertScore:   roundScore(score.Cert),
		HeaderScore: roundScore(score.Headers),
	}
}

func betterHostHeaderDiagnostic(current, next *hostHeaderDiagnostic) *hostHeaderDiagnostic {
	if current == nil {
		return next
	}
	if next == nil {
		return current
	}
	if next.Score != current.Score {
		if next.Score > current.Score {
			return next
		}
		return current
	}
	if current.StatusCode == 0 && next.StatusCode != 0 {
		return next
	}
	return current
}

func topHostHeaderDiagnostics(diagnostics []hostHeaderDiagnostic) []hostHeaderDiagnostic {
	var baseline []hostHeaderDiagnostic
	var rejects []hostHeaderDiagnostic
	for _, d := range diagnostics {
		if d.Event == "baseline" {
			baseline = append(baseline, d)
			continue
		}
		rejects = append(rejects, d)
	}
	sort.Slice(rejects, func(i, j int) bool {
		if rejects[i].Score != rejects[j].Score {
			return rejects[i].Score > rejects[j].Score
		}
		return rejects[i].IP < rejects[j].IP
	})
	if len(rejects) > hostHeaderMaxDiagnostics {
		rejects = rejects[:hostHeaderMaxDiagnostics]
	}
	return append(baseline, rejects...)
}

func hostHeaderDiagnosticCandidate(d hostHeaderDiagnostic) Candidate {
	return Candidate{
		Metadata: map[string]any{
			"diagnostic": map[string]any{
				"event":        d.Event,
				"message":      d.Message,
				"ip":           d.IP,
				"method":       d.Method,
				"url":          d.URL,
				"status_code":  d.StatusCode,
				"reason":       d.Reason,
				"score":        d.Score,
				"html_score":   d.HTMLScore,
				"cert_score":   d.CertScore,
				"header_score": d.HeaderScore,
			},
		},
	}
}

func hostHeaderProbeURL(ip netip.Addr, ep hostHeaderEndpoint) string {
	return fmt.Sprintf("%s://%s/", ep.Scheme, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", ep.Port)))
}

func canonicalTargetHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return target
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			target = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return strings.Trim(target, "[]")
}

func isInvalidHostHeaderSeed(ip netip.Addr) bool {
	return !ip.IsValid() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		cdn.IsCDNIP(ip)
}

func setHostHeaderBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="131", "Not_A Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func normalizeHostHeaderHTML(raw string) (text string, title string) {
	doc, err := html.Parse(strings.NewReader(raw))
	if err != nil {
		return normalizeWhitespace(stripHTMLTags(raw)), ""
	}
	var parts []string
	var walk func(*html.Node, bool)
	walk = func(n *html.Node, skip bool) {
		if n.Type == html.ElementNode {
			name := strings.ToLower(n.Data)
			if name == "script" || name == "style" || name == "noscript" || name == "svg" {
				skip = true
			}
			if name == "title" {
				title = normalizeWhitespace(nodeText(n))
			}
		}
		if !skip && n.Type == html.TextNode {
			if s := normalizeWhitespace(n.Data); s != "" {
				parts = append(parts, s)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, skip)
		}
	}
	walk(doc, false)
	return normalizeWhitespace(strings.Join(parts, " ")), title
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(cur *html.Node) {
		if cur.Type == html.TextNode {
			b.WriteString(cur.Data)
			b.WriteByte(' ')
		}
		for c := cur.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

func stripHTMLTags(raw string) string {
	var b strings.Builder
	inTag := false
	for _, r := range raw {
		switch r {
		case '<':
			inTag = true
		case '>':
			inTag = false
		default:
			if !inTag {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

func textSimilarity(a, b string) float64 {
	if a == b && a != "" {
		return 1
	}
	ta := strings.Fields(a)
	tb := strings.Fields(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	counts := map[string]int{}
	for _, t := range ta {
		counts[t]++
	}
	common := 0
	for _, t := range tb {
		if counts[t] > 0 {
			common++
			counts[t]--
		}
	}
	return float64(2*common) / float64(len(ta)+len(tb))
}

func certSimilarity(a, b *x509.Certificate) float64 {
	if a == nil || b == nil {
		return 0
	}
	score := 0.0
	if a.SerialNumber != nil && b.SerialNumber != nil && a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		score += 0.50
	}
	if a.Subject.CommonName != "" && strings.EqualFold(a.Subject.CommonName, b.Subject.CommonName) {
		score += 0.25
	}
	refSANs := map[string]bool{}
	for _, san := range a.DNSNames {
		refSANs[strings.ToLower(san)] = true
	}
	if len(refSANs) > 0 {
		overlap := 0
		for _, san := range b.DNSNames {
			if refSANs[strings.ToLower(san)] {
				overlap++
			}
		}
		if overlap > 0 {
			score += 0.25 * float64(overlap) / float64(len(refSANs))
		}
	}
	return score
}

func compareHostHeaderHeaders(a, b http.Header) float64 {
	total := 0
	matches := 0
	for _, h := range []string{"Server", "X-Powered-By"} {
		av, bv := a.Get(h), b.Get(h)
		if av == "" && bv == "" {
			continue
		}
		total++
		if strings.EqualFold(av, bv) {
			matches++
		}
	}
	ac, bc := cookieNames(a.Values("Set-Cookie")), cookieNames(b.Values("Set-Cookie"))
	if len(ac) > 0 || len(bc) > 0 {
		total++
		for name := range ac {
			if bc[name] {
				matches++
				break
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(matches) / float64(total)
}

func cookieNames(raw []string) map[string]bool {
	out := map[string]bool{}
	for _, c := range raw {
		name, _, _ := strings.Cut(c, "=")
		name = strings.TrimSpace(strings.ToLower(name))
		if name != "" {
			out[name] = true
		}
	}
	return out
}

func statusAdjustment(a, b int) float64 {
	if a == b {
		if a >= 400 {
			return -hostHeaderGenericErrorPenalty
		}
		return 0.05
	}
	aOK := a >= 200 && a < 400
	bOK := b >= 200 && b < 400
	if aOK != bOK {
		return -0.20
	}
	return 0
}

func isGenericHostHeaderMatch(baseStatus, probeStatus int) bool {
	if baseStatus >= 400 && probeStatus >= 400 {
		return true
	}
	return false
}

func isWeakShortHostHeaderMatch(base baseline, p hostHeaderProbe, score hostHeaderScore) bool {
	if len(base.Text) >= hostHeaderMinBodyTextLen && len(p.Text) >= hostHeaderMinBodyTextLen {
		return false
	}
	// Very short pages can match by accident. Keep them only when a stronger
	// identity signal explains the match, such as a shared TLS cert or title.
	return score.Cert < 0.50 && !score.Title
}

func roundScore(v float64) float64 {
	return math.Round(v*1000) / 1000
}

func atoiDefault(s string, fallback int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return fallback
	}
	return n
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
	return strings.Contains(via, "cloudfront") ||
		strings.Contains(via, "cloudflare") ||
		strings.Contains(xc, "cloudfront") ||
		strings.Contains(xc, "cloudflare")
}

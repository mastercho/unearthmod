package techniques

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

func init() { Register(bannerGrabTechnique{}) }

// bannerGrabTechnique probes each candidate IP on a small fixed list of
// common service ports and reads the welcome banner. Banners reveal
// server software (SSH version, SMTP greeting, HTTP Server header) that
// is consistent with — though not proof of — an origin host. The 0.45
// weight reflects its corroborative role: a banner on its own does not
// confirm an origin, but pair it with a host_header match and the
// noisy-OR rule raises confidence dramatically.
//
// Tier: Active. Phase-2 consumer (RunOptions.SeedIPs from phase 1).
type bannerGrabTechnique struct{}

func (bannerGrabTechnique) Name() string             { return "banner_grab" }
func (bannerGrabTechnique) Tier() Tier               { return TierActive }
func (bannerGrabTechnique) RequiresAPIKey() bool     { return false }
func (bannerGrabTechnique) DefaultWeight() float64   { return 0.45 }
func (bannerGrabTechnique) ConsumesCandidates() bool { return true }

// bannerPorts is the small set of ports likely to surface useful
// origin-identifying banners. Kept short on purpose: this is recon, not
// portscanning. 80 + 443 are mostly here for the HTTP Server header,
// which complements host_header.
var bannerPorts = []int{21, 22, 25, 80, 443}

const (
	bannerWorkers   = 50
	bannerReadLimit = 1024
	bannerDeadline  = 2 * time.Second
)

// portDialer is the dial surface banner_grab depends on. Tests replace
// the package var bannerDial with a fake that returns canned banners
// without opening real sockets. The default uses net.Dialer.
type portDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var bannerDial portDialer = &net.Dialer{Timeout: bannerDeadline}

func (bannerGrabTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if len(opts.SeedIPs) == 0 {
		return nil, nil
	}

	type job struct {
		ip   netip.Addr
		port int
	}
	type result struct {
		ip     netip.Addr
		port   int
		banner string
	}
	in := make(chan job)
	outc := make(chan result)

	var wg sync.WaitGroup
	for i := 0; i < bannerWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range in {
				banner := grabBanner(ctx, j.ip, j.port)
				if banner == "" {
					continue
				}
				select {
				case outc <- result{ip: j.ip, port: j.port, banner: banner}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, ip := range opts.SeedIPs {
			for _, p := range bannerPorts {
				select {
				case in <- job{ip: ip, port: p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(outc) }()

	// One Candidate per (ip, port) hit. host_header still gets one entry
	// for the whole IP; banner_grab is intentionally noisier so distinct
	// services on the same IP all show up as separate evidence rows.
	// They share an IP and so will fold into one ScoredIP in the engine.
	var cands []Candidate
	for r := range outc {
		token := summarizeBanner(r.port, r.banner)
		_ = target // target is informational only here
		cands = append(cands, Candidate{
			IP: r.ip.String(),
			Evidence: fmt.Sprintf(
				"banner_grab: %s:%d announced %q", r.ip, r.port, token),
		})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Evidence < cands[j].Evidence })
	return cands, nil
}

func grabBanner(ctx context.Context, ip netip.Addr, port int) string {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	if ip.Is6() {
		addr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	dialCtx, cancel := context.WithTimeout(ctx, bannerDeadline)
	defer cancel()
	conn, err := bannerDial.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	// HTTP doesn't speak first — send a minimal probe so we get the
	// Server header in the response. SSH/SMTP/FTP announce themselves.
	if port == 80 || port == 443 {
		req := "HEAD / HTTP/1.0\r\n\r\n"
		_ = conn.SetWriteDeadline(time.Now().Add(bannerDeadline))
		if _, err := conn.Write([]byte(req)); err != nil {
			return ""
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(bannerDeadline))
	buf := make([]byte, bannerReadLimit)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		return ""
	}
	return string(buf[:n])
}

// summarizeBanner extracts an identifying token from the raw banner so
// the Evidence string is informative without being huge. Token rules:
//
//   - SSH: take the first line; it starts with "SSH-".
//   - SMTP: the 220-line.
//   - FTP: the 220 banner.
//   - HTTP: the Server header value.
func summarizeBanner(port int, banner string) string {
	switch port {
	case 22, 25, 21:
		return strings.TrimSpace(firstLine(banner))
	case 80, 443:
		// Look for "Server: foo" header line.
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			if low := strings.ToLower(line); strings.HasPrefix(low, "server:") {
				return strings.TrimSpace(line[len("server:"):])
			}
		}
		return strings.TrimSpace(firstLine(banner))
	default:
		return strings.TrimSpace(firstLine(banner))
	}
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

package techniques

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestExpandConfirmedNeighborsIPv4Slash24(t *testing.T) {
	neighbors := expandConfirmedNeighbors([]netip.Addr{netip.MustParseAddr("203.0.113.50")})
	if len(neighbors) != 253 {
		t.Fatalf("neighbors len = %d, want 253", len(neighbors))
	}
	for _, ip := range neighbors {
		if ip == netip.MustParseAddr("203.0.113.50") {
			t.Fatal("seed IP should be excluded from neighbor scan")
		}
		if ip.String() == "203.0.113.0" || ip.String() == "203.0.113.255" {
			t.Fatalf("network/broadcast address should be excluded: %s", ip)
		}
	}
}

func TestNeighborScanConfirmsMatchingNeighbor(t *testing.T) {
	body := "<html><body>" + strings.Repeat("origin body ", 60) + "</body></html>"
	rt := &hostHeaderStubRT{
		baselineBody: body,
		byURL: map[string]func(*http.Request) (*http.Response, error){
			"https://203.0.113.51:443/": func(req *http.Request) (*http.Response, error) {
				if req.Host != "example.test" {
					return stubResponse(200, "direct placeholder"), nil
				}
				return stubResponse(200, body), nil
			},
			"https://203.0.113.50:443/": func(*http.Request) (*http.Response, error) {
				t.Fatal("seed IP must not be reprobed as its own neighbor")
				return nil, io.ErrUnexpectedEOF
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withHostHeaderClient(t, hc)

	out, err := neighborScanTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		SeedIPs:    []netip.Addr{netip.MustParseAddr("203.0.113.50")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var matches []Candidate
	for _, c := range out {
		if c.IP != "" {
			matches = append(matches, c)
		}
	}
	if len(matches) != 1 || matches[0].IP != "203.0.113.51" {
		t.Fatalf("expected matching neighbor .51, got %+v", out)
	}
	if !strings.Contains(matches[0].Evidence, "neighbor_scan") {
		t.Fatalf("evidence should mention neighbor_scan: %q", matches[0].Evidence)
	}
	v, ok := matches[0].Metadata["validation"].(map[string]any)
	if !ok {
		t.Fatalf("validation metadata missing: %+v", matches[0].Metadata)
	}
	if v["technique"] != "neighbor_scan" {
		t.Fatalf("validation technique = %v, want neighbor_scan", v["technique"])
	}
	if v["method"] != "host_header_neighbor" {
		t.Fatalf("validation method = %v, want host_header_neighbor", v["method"])
	}
	if len(out) != 2 || out[1].Metadata["diagnostic"] == nil {
		t.Fatalf("neighbor summary diagnostic missing: %+v", out)
	}
}

func TestNeighborScanNoSeedsNoOp(t *testing.T) {
	out, err := neighborScanTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil || out != nil {
		t.Fatalf("no seeds: err=%v out=%v", err, out)
	}
}

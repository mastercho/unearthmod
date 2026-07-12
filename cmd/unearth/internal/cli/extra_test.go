package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/unearth-tool/unearth/pkg/techniques"
	"github.com/unearth-tool/unearth/pkg/unearth"
)

func TestTableSink_Colorized(t *testing.T) {
	// Drive the table sink directly with color enabled and verify ANSI
	// sequences are present at each band.
	s := &tableSink{top: 0, color: true}
	res := &unearth.Result{
		Target: "x",
		Candidates: []unearth.ScoredIP{
			{IP: "1.1.1.1", Score: 0.95, Corroboration: 3, Validation: &unearth.Validation{Status: "confirmed", Score: 0.91}, Techniques: []unearth.TechniqueHit{{Name: "a"}}},
			{IP: "2.2.2.2", Score: 0.60, Corroboration: 1, Techniques: []unearth.TechniqueHit{{Name: "b"}}},
			{IP: "3.3.3.3", Score: 0.20, Corroboration: 1, Techniques: []unearth.TechniqueHit{{Name: "c"}}},
		},
		Errors:   []unearth.TechniqueErr{{Technique: "x", Err: "boom"}},
		Warnings: []string{"warn-x"},
	}
	var out bytes.Buffer
	if err := s.write(&out, nil, res, &rootFlags{}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{ansiGreen, ansiYellow, ansiRed, "confirmed 0.91", "candidate", "warn-x", "boom"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q\n---\n%s", want, got)
		}
	}
}

func TestVerbose_AnnouncesCredentialStatus(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target), nil
	})
	code, _, stderr := captured(t, "--verbose", "--active", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr, "censys") || !strings.Contains(stderr, "shodan") {
		t.Errorf("credential status not announced under --verbose:\n%s", stderr)
	}
}

func TestVerbose_EmitsResultMetaOnStderrForJSONL(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		r := fakeResult(target, "203.0.113.1")
		r.Warnings = []string{"w1"}
		r.Errors = []unearth.TechniqueErr{{Technique: "t", Err: "e", Reason: "missing_api_key"}}
		r.TechniqueRuns = []unearth.TechniqueRun{{Technique: "phpinfo_scan", Status: "ok", Candidates: 0}}
		r.Candidates[0].Validation = &unearth.Validation{
			Status:      "confirmed",
			Technique:   "host_header",
			Method:      "host_header",
			URL:         "https://203.0.113.1:443/",
			Scheme:      "https",
			Port:        443,
			StatusCode:  200,
			Score:       0.82,
			HTMLScore:   0.74,
			CertScore:   1,
			HeaderScore: 0.33,
		}
		return r, nil
	})
	code, stdout, stderr := captured(t, "--verbose", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// stdout should have the candidate jsonl, NOT the metadata.
	if !strings.Contains(stdout, "203.0.113.1") {
		t.Errorf("stdout missing candidate: %q", stdout)
	}
	if strings.Contains(stdout, "warn:") || strings.Contains(stdout, "CDN:") {
		t.Errorf("stdout should not carry result metadata: %q", stdout)
	}
	// stderr should mention CDN, run summary, confirmation, warning, error reason,
	// and the final human origin block.
	for _, want := range []string{
		"CDN: cloudflare",
		"run[phpinfo_scan]",
		"candidates=0",
		"confirmed[203.0.113.1]",
		"host_header",
		"warn:",
		"missing_api_key",
		"POSSIBLE WAF BYPASS FOUND",
		"IP:           203.0.113.1",
		"Port:         443",
		"Method:       host_header",
		"Overall:      82.0%",
		"Status:       200",
		`Verify:       curl -sk --resolve "example.test:443:203.0.113.1" https://example.test:443/`,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if !strings.Contains(stdout, `"status":"confirmed"`) {
		t.Errorf("stdout should include confirmed status: %q", stdout)
	}
}

func TestOriginVerifyCommandAlwaysPinsCandidateIP(t *testing.T) {
	hostHeader := originVerifyCommand("www.example.test", "203.0.113.20", &unearth.Validation{
		Method: "host_header",
		URL:    "https://www.example.test/",
		Scheme: "https",
		Port:   443,
	})
	wantHostHeader := `curl -sk --resolve "www.example.test:443:203.0.113.20" https://www.example.test:443/`
	if hostHeader != wantHostHeader {
		t.Fatalf("host-header verify command:\nwant: %s\n got: %s", wantHostHeader, hostHeader)
	}

	direct := originVerifyCommand("www.example.test", "203.0.113.21", &unearth.Validation{
		Method: "direct",
		URL:    "https://www.example.test/",
		Scheme: "https",
		Port:   443,
	})
	if want := "curl -sk https://203.0.113.21:443/"; direct != want {
		t.Fatalf("direct verify command:\nwant: %s\n got: %s", want, direct)
	}
}

func TestVerbose_EmitsNoConfirmedOriginSummary(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		r := fakeResult(target, "203.0.113.10")
		r.TechniqueRuns = []unearth.TechniqueRun{{Technique: "host_header", Status: "ok", Candidates: 0}}
		return r, nil
	})
	code, stdout, stderr := captured(t, "--verbose", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, `"status":"candidate"`) {
		t.Errorf("stdout should include candidate status: %q", stdout)
	}
	if !strings.Contains(stderr, "no confirmed origin; showing ranked candidates only") {
		t.Errorf("stderr missing no-confirmed summary:\n%s", stderr)
	}
}

func TestVerbose_EmitsHostHeaderDiagnostics(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		r := fakeResult(target, "203.0.113.10")
		r.TechniqueRuns = []unearth.TechniqueRun{{
			Technique:  "host_header",
			Status:     "ok",
			Candidates: 0,
			Diagnostics: []unearth.TechniqueDiagnostic{
				{Event: "baseline", StatusCode: 200, URL: "https://example.test/", Message: "baseline fetched"},
				{Event: "reject", IP: "203.0.113.10", Method: "host_header", StatusCode: 200, Score: 0.42, HTMLScore: 0.4, CertScore: 0.1, HeaderScore: 0.2, Reason: "below_threshold", URL: "https://203.0.113.10/"},
			},
		}}
		return r, nil
	})
	code, _, stderr := captured(t, "--verbose", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"diag[host_header] baseline", "diag[host_header] reject", "below_threshold", "score=0.42"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

func TestUsageError_HasStableErrorString(t *testing.T) {
	e := errUsage("nope").(*usageError)
	if e.Error() != "nope" || e.code != exitUsageError {
		t.Errorf("usageError: %+v", e)
	}
}

func TestNewSink_InvalidFormatRejected(t *testing.T) {
	if _, err := newSink("xml", false, 0); err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestCapN(t *testing.T) {
	if capN(0, 5) != 5 {
		t.Error("top<=0 means uncapped")
	}
	if capN(10, 3) != 3 {
		t.Error("top>=have means uncapped")
	}
	if capN(2, 5) != 2 {
		t.Error("top<have should clamp")
	}
}

func TestColorScore_BandsAndReset(t *testing.T) {
	s := &tableSink{color: true}
	if s.colorScore(0.9) != ansiGreen {
		t.Errorf("high band: %q", s.colorScore(0.9))
	}
	if s.colorScore(0.6) != ansiYellow {
		t.Errorf("mid band: %q", s.colorScore(0.6))
	}
	if s.colorScore(0.1) != ansiRed {
		t.Errorf("low band: %q", s.colorScore(0.1))
	}
}

func TestEmitResultMeta_HandlesEmptyResult(t *testing.T) {
	var w bytes.Buffer
	emitResultMeta(&w, &unearth.Result{Target: "x"})
	if w.Len() != 0 {
		t.Errorf("empty result should produce no output, got %q", w.String())
	}
}

func TestTierNotice_QuietWhenPassive(t *testing.T) {
	var w bytes.Buffer
	announceTierNotice(&w, techniques.TierPassive)
	if w.Len() != 0 {
		t.Errorf("passive tier should not announce: %q", w.String())
	}
}

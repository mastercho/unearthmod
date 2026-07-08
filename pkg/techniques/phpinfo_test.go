package techniques

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestPHPInfoScan_ExtractsServerAddress(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/phpinfo.php": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, phpInfoBody(`
				<tr><td class="e">SERVER_ADDR </td><td class="v">198.51.100.42</td></tr>
				<tr><td class="e">REMOTE_ADDR </td><td class="v">198.51.100.99</td></tr>
			`)), nil
		},
	})

	out, err := phpInfoTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "198.51.100.42" {
		t.Fatalf("want SERVER_ADDR candidate only, got %+v", out)
	}
	if strings.Contains(out[0].Evidence, "REMOTE_ADDR") || !strings.Contains(out[0].Evidence, "SERVER_ADDR") {
		t.Fatalf("evidence should name SERVER_ADDR only, got %q", out[0].Evidence)
	}
	if !strings.Contains(strings.Join(rt.calls, "\n"), "/phpinfo.php") {
		t.Fatalf("expected scan to include the nuclei phpinfo path list, calls: %v", rt.calls)
	}
}

func TestPHPInfoScan_FiltersUnroutableAndCDN(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/php.php": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, phpInfoBody(`
				<tr><td class="e">SERVER_ADDR </td><td class="v">10.0.0.5</td></tr>
				<tr><td class="e">LOCAL_ADDR </td><td class="v">104.16.0.5</td></tr>
			`)), nil
		},
	})

	out, err := phpInfoTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("want filtered empty result, got %+v", out)
	}
}

func TestPHPInfoScan_RequiresPHPInfoMatcher(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/php.php": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, "<html>PHP Version but no extension marker SERVER_ADDR 198.51.100.42</html>"), nil
		},
		"https://example.test/php2.php": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, phpInfoBody(`SERVER_ADDR 198.51.100.42`)), nil
		},
	})

	out, err := phpInfoTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("want no candidates without status 200 and phpinfo words, got %+v", out)
	}
}

func TestPHPInfoScan_ContextCancellation(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/php.php": func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := phpInfoTechnique{}.Run(ctx, "example.test", RunOptions{HTTPClient: hc})
	if err == nil {
		t.Fatal("expected ctx error")
	}
}

func TestPHPInfoTechnique_Metadata(t *testing.T) {
	p := phpInfoTechnique{}
	if p.Name() != "phpinfo_scan" || p.Tier() != TierAggressive || p.RequiresAPIKey() || p.DefaultWeight() != 0.74 {
		t.Errorf("metadata wrong: %+v", p)
	}
}

func phpInfoBody(extra string) string {
	return `<html><body><h1>PHP Version 8.3.0</h1><table>` + extra + `</table><h2>PHP Extension</h2></body></html>`
}

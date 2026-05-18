package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/unearth-tool/unearth/pkg/techniques"

	_ "github.com/unearth-tool/unearth/pkg/techniques"
)

// newTestServer builds an MCPServer with all tools registered and no real keys.
func newTestServer(t *testing.T) *server.MCPServer {
	t.Helper()
	keys := techniques.APIKeys{} // no keys — tests the keyless path
	s := server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(false))
	registerDiscover(s, keys)
	registerCertFingerprint(s, keys)
	registerDNSHistory(s, keys)
	registerSubdomainEnum(s, keys)
	registerHostHeaderProbe(s, keys)
	return s
}

// callTool invokes a tool by name by getting its handler and calling it directly.
func callTool(t *testing.T, s *server.MCPServer, toolName string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	st := s.GetTool(toolName)
	if st == nil {
		t.Fatalf("tool %q not registered", toolName)
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = toolName
	req.Params.Arguments = args
	result, err := st.Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("tool handler %q returned unexpected transport error: %v", toolName, err)
	}
	return result
}

// ── unearth_discover ─────────────────────────────────────────────────────────

func TestDiscover_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_discover", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error result for missing target, got non-error")
	}
}

func TestDiscover_EmptyTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_discover", map[string]any{"target": ""})
	if !res.IsError {
		t.Fatal("expected error result for empty target")
	}
}

// ── unearth_cert_fingerprint ─────────────────────────────────────────────────

func TestCertFingerprint_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_cert_fingerprint", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error for missing target")
	}
}

func TestCertFingerprint_EmptyTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_cert_fingerprint", map[string]any{"target": ""})
	if !res.IsError {
		t.Fatal("expected error for empty target")
	}
}

// ── unearth_dns_history ───────────────────────────────────────────────────────

func TestDNSHistory_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_dns_history", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error for missing target")
	}
}

// ── unearth_subdomain_enum ────────────────────────────────────────────────────

func TestSubdomainEnum_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_subdomain_enum", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error for missing target")
	}
}

// ── unearth_host_header_probe ─────────────────────────────────────────────────

func TestHostHeaderProbe_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_host_header_probe", map[string]any{
		"ips": []any{"1.2.3.4"},
	})
	if !res.IsError {
		t.Fatal("expected error for missing target")
	}
}

func TestHostHeaderProbe_MissingIPs(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_host_header_probe", map[string]any{
		"target": "example.com",
	})
	if !res.IsError {
		t.Fatal("expected error for missing ips")
	}
}

func TestHostHeaderProbe_EmptyIPList(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_host_header_probe", map[string]any{
		"target": "example.com",
		"ips":    []any{},
	})
	if !res.IsError {
		t.Fatal("expected error for empty ips list")
	}
}

func TestHostHeaderProbe_InvalidIPsFiltered(t *testing.T) {
	// All entries are non-IP strings — after filtering, seedIPs is empty.
	s := newTestServer(t)
	res := callTool(t, s, "unearth_host_header_probe", map[string]any{
		"target": "example.com",
		"ips":    []any{"not-an-ip", 42.0, nil},
	})
	if !res.IsError {
		t.Fatal("expected error when all ips entries are invalid")
	}
}

// ── keyless path (no API keys) ────────────────────────────────────────────────

func TestKeylessPath_ServerBuildsWithNoKeys(t *testing.T) {
	// The server must register all tools without panicking when no API keys are set.
	s := newTestServer(t)
	if s == nil {
		t.Fatal("server is nil")
	}
	// Verify all five tools are registered.
	tools := []string{
		"unearth_discover",
		"unearth_cert_fingerprint",
		"unearth_dns_history",
		"unearth_subdomain_enum",
		"unearth_host_header_probe",
	}
	for _, name := range tools {
		if s.GetTool(name) == nil {
			t.Errorf("tool %q not registered on keyless server", name)
		}
	}
}

// ── result shape ─────────────────────────────────────────────────────────────

func TestResultJSON_WellFormed(t *testing.T) {
	type sample struct {
		Foo string `json:"foo"`
	}
	out := resultToJSON(sample{Foo: "bar"})
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("resultToJSON produced invalid JSON: %v — output: %s", err, out)
	}
	if m["foo"] != "bar" {
		t.Fatalf("expected foo=bar, got %v", m["foo"])
	}
}

// ── baseOpts tier parsing ─────────────────────────────────────────────────────

func TestBaseOpts_TierParsing(t *testing.T) {
	cases := []struct {
		in   string
		want techniques.Tier
	}{
		{"passive", techniques.TierPassive},
		{"active", techniques.TierActive},
		{"aggressive", techniques.TierAggressive},
		{"", techniques.TierPassive},
		{"unknown", techniques.TierPassive},
	}
	for _, tc := range cases {
		got := baseOpts(tc.in, techniques.APIKeys{}).Tier
		if got != tc.want {
			t.Errorf("baseOpts(%q).Tier = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// ── MCP server does not panic on a bad tool call ──────────────────────────────

func TestBadToolCall_UnknownTool(t *testing.T) {
	s := newTestServer(t)
	// GetTool returns nil for unknown tools — that is the expected behavior.
	if st := s.GetTool("nonexistent_tool"); st != nil {
		t.Fatalf("expected nil for unknown tool, got %v", st)
	}
}

// ── dns_history returns key-missing error with no keys ────────────────────────

func TestDNSHistory_KeyMissingError(t *testing.T) {
	// With no API keys, dns_history requires a key and the handler returns an
	// IsError result (via RunTechnique's RequiresAPIKey check), not a panic.
	s := newTestServer(t)
	res := callTool(t, s, "unearth_dns_history", map[string]any{"target": "example.com"})
	if !res.IsError {
		t.Fatal("expected IsError=true for dns_history with no keys, got non-error")
	}
}

// ── subdomain_enum: valid target, no keys (no key required) ──────────────────

func TestSubdomainEnum_ValidTarget_NoKeys(t *testing.T) {
	// subdomain_enum doesn't require an API key. With a cancelled context,
	// the tool should return a tool-level error (context cancelled), not panic.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := newTestServer(t)
	st := s.GetTool("unearth_subdomain_enum")
	if st == nil {
		t.Fatal("unearth_subdomain_enum not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_subdomain_enum"
	req.Params.Arguments = map[string]any{"target": "example.com"}
	// Use the cancelled context directly — the handler receives it and passes
	// it through to RunTechnique, which honours context cancellation.
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	// Result may or may not be IsError depending on how quickly the technique
	// sees the cancellation, but it must not panic.
	_ = result
}

// ── cert_fingerprint: valid target, no keys (only ct_fingerprint runs) ───────

func TestCertFingerprint_ValidTarget_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := newTestServer(t)
	st := s.GetTool("unearth_cert_fingerprint")
	if st == nil {
		t.Fatal("unearth_cert_fingerprint not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_cert_fingerprint"
	req.Params.Arguments = map[string]any{"target": "example.com"}
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	_ = result
}

// ── host_header_probe: valid target + IPs, cancelled context ─────────────────

func TestHostHeaderProbe_ValidArgs_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := newTestServer(t)
	st := s.GetTool("unearth_host_header_probe")
	if st == nil {
		t.Fatal("unearth_host_header_probe not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_host_header_probe"
	req.Params.Arguments = map[string]any{
		"target": "example.com",
		"ips":    []any{"1.2.3.4"},
	}
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	_ = result
}

// ── discover: valid target, cancelled context ─────────────────────────────────

func TestDiscover_ValidTarget_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := newTestServer(t)
	st := s.GetTool("unearth_discover")
	if st == nil {
		t.Fatal("unearth_discover not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_discover"
	req.Params.Arguments = map[string]any{"target": "example.com"}
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	// With cancelled context, Discover returns a "context cancelled" error —
	// the handler should surface it as IsError=true, not panic.
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

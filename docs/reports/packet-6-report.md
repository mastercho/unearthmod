# Packet 6 Report — MCP Server & CDN Dataset Upgrade

**Date:** 2026-05-17
**Branch:** main

---

## 1. Status

**DONE.** Both Part A (MCP server) and Part B (CDN dataset upgrade) are complete. All checkpoints green.

---

## 2. Checkpoint Results

```
go build ./...                    PASS
CGO_ENABLED=0 go build ./...      PASS
go vet ./...                      PASS
gofmt -l .                        (empty)
go test -race ./...               PASS (all packages)
go mod tidy                       PASS (no unexpected changes)
make build                        PASS (both binaries built to dist/)
make mcp                          PASS (unearth-mcp built to dist/)
```

**All 8 checkpoint commands green.**

---

## 3. MCP Library

**Library chosen:** `github.com/mark3labs/mcp-go` at `v0.48.0`

**Why v0.48.0 specifically:** The latest `mark3labs/mcp-go` releases (v0.49.0+) require Go 1.25 in their `go.mod`. Since Go 1.21+, the `go` directive is a hard minimum enforced by the toolchain; a project at Go 1.23.0 cannot build a dependency that declares Go 1.25. Version v0.48.0 is the last release that declares `go 1.23.0` and is therefore the correct pin for this project's floor.

**Why mcp-go over the official SDK:**
- The official `modelcontextprotocol/go-sdk` (v1.6.0) requires Go 1.25 — unusable at Go 1.23.
- `mark3labs/mcp-go` is the most popular Go MCP library (8,700+ GitHub stars), actively maintained, and MIT licensed.
- The official SDK's README acknowledges mcp-go as the inspiration.

**MCP protocol version:** mcp-go v0.48.0 implements the 2025-03-26 MCP spec. The 2025-11-25 spec (latest) requires v0.49.0+.

**License:** MIT (confirmed from repo).

**Stdio transport:** `server.ServeStdio(s)` — reads JSON-RPC requests from `os.Stdin`, writes responses to `os.Stdout`. All diagnostics go to `os.Stderr` via `fmt.Fprintf(os.Stderr, ...)`. Stdout is the sole protocol channel.

---

## 4. MCP Tools

Five tools are registered in `cmd/unearth-mcp/main.go`:

| Tool | Required params | Optional params | Library call | Result shape |
|---|---|---|---|---|
| `unearth_discover` | `target` (string) | `tier` (passive/active/aggressive) | `unearth.Discover(ctx, target, opts)` | `*unearth.Result` as JSON |
| `unearth_cert_fingerprint` | `target` (string) | — | `unearth.RunTechnique(ctx, name, target, opts, nil)` per technique | `[]techResult` as JSON |
| `unearth_dns_history` | `target` (string) | — | `unearth.RunTechnique(ctx, "dns_history", ...)` | `[]techniques.Candidate` as JSON |
| `unearth_subdomain_enum` | `target` (string) | — | `unearth.RunTechnique(ctx, "subdomain_enum", ...)` | `[]techniques.Candidate` as JSON |
| `unearth_host_header_probe` | `target` (string), `ips` (array of strings) | — | `unearth.RunTechnique(ctx, "host_header", ..., seedIPs)` | `[]techniques.Candidate` as JSON |

**`pkg/unearth` helper added:** `RunTechnique(ctx, name, target, opts Options, seedIPs []string) ([]techniques.Candidate, error)`. This is a clean exported function that:
1. Looks up the technique by name via `techniques.Get()`
2. Returns an error if the technique is not registered or requires a missing API key
3. Opens a cache store (if not opted out)
4. Constructs a rate limiter and HTTP client
5. Parses `seedIPs` strings to `netip.Addr` values for phase-2 consumer techniques
6. Applies per-technique timeout via the existing `techniqueTimeout()` helper
7. Calls `t.Run(ctx, target, runOpts)` and returns the raw candidates

`unearth_cert_fingerprint` runs `ct_fingerprint` always (keyless), plus `censys_cert` and `shodan_cert` only when their respective API keys are present in the environment.

---

## 5. MCP Robustness

**Panics contained:** `server.WithRecovery()` is passed to `NewMCPServer`. The library wraps every tool handler in a recover() so a panic in a handler does not crash the server process.

**Parameter validation:** Each handler calls `req.RequireString("target")` for the target parameter. If missing or empty, the handler returns `mcp.NewToolResultError(...)` — a tool-level error response, not a transport error. For `host_header_probe`, the `ips` array is type-asserted and each entry is validated with `netip.ParseAddr`; a completely invalid or empty list returns a tool-level error immediately.

**stdout purity:** The `main()` function only writes to `os.Stderr` on fatal startup error. Tool handlers return `*mcp.CallToolResult` to the library; the library serializes the JSON-RPC response to stdout. No `fmt.Println`, `log.Print`, or `os.Stdout` writes appear anywhere in the MCP command.

**Context cancellation:** All library calls (`Discover`, `RunTechnique`) propagate the context from the MCP layer. A context cancel or deadline terminates the discovery run cleanly.

---

## 6. CDN Dataset

**Sources chosen:**

| Provider | Source | URL | Format | Update frequency |
|---|---|---|---|---|
| Cloudflare | First-party | `https://www.cloudflare.com/ips-v4` and `/ips-v6` | Plain text, one CIDR per line | Infrequent; no SLA |
| CloudFront (AWS) | First-party | `https://ip-ranges.amazonaws.com/ip-ranges.json` | JSON; `service: "CLOUDFRONT"` filtered | Multiple times per week |
| Fastly | First-party | `https://api.fastly.com/public-ip-list` | JSON `{"addresses":[...],"ipv6_addresses":[...]}` | Maintained by Fastly |
| Sucuri | Hardcoded from docs | Sucuri WAF troubleshooting guide | N/A | Stable; checked 2026-05-17 |

**Embedded snapshot date:** `SnapshotDate = "2026-05-17"` (updated from 2026-05-16).

**Snapshot model preserved:** All four providers are embedded via `//go:embed data/*.txt` and `//go:embed data/*.json`. The binary works with zero network access.

**Refresh mechanism:** `Refresh(ctx, hc)` fetches fresh data from Cloudflare, CloudFront, and Fastly endpoints, rebuilds the in-memory provider tables, and writes the fetched bytes to `$XDG_CACHE_HOME/unearth/cdn/*.{txt,json}`.

**On-disk cache vs embedded snapshot:** `LoadCachedRefresh()` reads from the XDG cache directory and, if files exist and are newer than 24h, loads them into memory — overriding the embedded snapshot. This is called at process start by the CLI's cache-refresh flow and the MCP server's future startup hook. If no fresh cache exists, the embedded snapshot remains active.

---

## 7. CDN Coverage

**v1.0 providers:**

| Provider | IP range source | Header signals | DNS signals |
|---|---|---|---|
| Cloudflare | Embedded + refreshable snapshot | `server: cloudflare`, `cf-ray` | `.cloudflare.net`, `.cloudflare.com`, `.ns.cloudflare.com` |
| CloudFront | Embedded + refreshable snapshot | `x-amz-cf-id`, `via: cloudfront`, `x-cache: cloudfront` | `.cloudfront.net` |
| Fastly | **New**: embedded + refreshable snapshot | `x-fastly-request-id`, `x-served-by: cache-*` | `.fastly.net`, `.fastlylb.net` |
| Sucuri | **New**: hardcoded (docs-sourced) | `x-sucuri-cache` | `.sucuri.net` |

**Akamai:** Not added. Akamai publishes no authoritative machine-readable IP range list. The community repo `platformbuilds/Akamai-ASN-and-IPs-List` is explicitly non-exhaustive. Adding Akamai with unreliable data would cause false negatives. Deferred to v1.1 with a note in docs.

**Existing callers unaffected:** `IsCDNIP`, `ProviderForIP`, and `Detect` signatures are unchanged. All existing techniques that call `cdn.IsCDNIP(a)` now also filter Fastly and Sucuri IPs as CDN ranges — which is correct behavior.

---

## 8. Coverage

| Package | Coverage |
|---|---|
| `cmd/unearth` | 0.0% (main fn, no tests — expected) |
| `cmd/unearth/internal/cli` | 85.5% |
| `cmd/unearth-mcp` | **81.2%** (new; target ≥70% ✓) |
| `internal/httpclient` | 100.0% |
| `internal/ratelimit` | 96.2% |
| `pkg/cache` | 86.2% |
| `pkg/cdn` | 82.7% |
| `pkg/config` | 92.9% |
| `pkg/rank` | 100.0% |
| `pkg/techniques` | 83.9% |
| `pkg/unearth` | 71.7% |

No package regressed. `cmd/unearth-mcp` hit 81.2% coverage.

---

## 9. Dependencies Added

| Module | Version | Purpose |
|---|---|---|
| `github.com/mark3labs/mcp-go` | v0.48.0 | MCP server library (direct) |
| `github.com/google/jsonschema-go` | v0.4.2 | Transitive (mcp-go) |
| `github.com/spf13/cast` | (transitive) | Transitive (mcp-go) |
| `github.com/yosida95/uritemplate/v3` | (transitive) | Transitive (mcp-go) |
| `github.com/davecgh/go-spew` | (transitive test) | Transitive (mcp-go test deps) |

All other dependencies are transitive pull-ins from mcp-go. No CGO dependencies; `CGO_ENABLED=0 go build ./...` passes.

---

## 10. Files Created / Changed

**New files:**
- `cmd/unearth-mcp/main.go` — full MCP server implementation (replaces stub)
- `cmd/unearth-mcp/main_test.go` — MCP tool handler tests
- `pkg/cdn/data/fastly-v4.txt` — embedded Fastly IPv4 ranges
- `pkg/cdn/data/fastly-v6.txt` — embedded Fastly IPv6 ranges
- `pkg/cdn/data/sucuri-v4.txt` — embedded Sucuri IPv4 ranges
- `pkg/cdn/data/sucuri-v6.txt` — embedded Sucuri IPv6 ranges
- `docs/reports/packet-6-report.md` — this file

**Modified Packet 1–5B files:**
- `pkg/cdn/cdn.go` — added Fastly + Sucuri providers, `RefreshFrom`, `LoadCachedRefresh`, `parseFastlyJSON`, header signals
- `pkg/cdn/cdn_test.go` — Fastly/Sucuri IP, DNS, header, parseFastlyJSON tests
- `pkg/cdn/refresh_test.go` — updated to use `RefreshFrom` with explicit URLs; added `LoadCachedRefresh` disk-cache test
- `pkg/unearth/unearth.go` — added `RunTechnique` exported helper
- `Makefile` — `mcp` target now builds `dist/unearth-mcp`
- `go.mod` / `go.sum` — mcp-go v0.48.0 and transitive deps

---

## 11. Decisions

- **mcp-go v0.48.0 pin:** Required by Go 1.23 floor constraint; v0.49.0+ breaks compatibility. Documented in the report.
- **Sucuri hardcoded:** Sucuri publishes no machine-readable endpoint; their 4 IPv4 + 1 IPv6 CIDRs are small and stable. Not added to the refresh mechanism.
- **`RefreshFrom` as testable core:** Rather than injecting URL parameters into `Refresh`, a `RefreshFrom(ctx, hc, refreshURLs{...})` function was extracted. Tests call `RefreshFrom` with test-server URLs. `Refresh` is a thin wrapper over `RefreshFrom` with the production URLs.
- **`LoadCachedRefresh` non-fatal:** Any failure in loading the XDG cache silently falls back to the embedded snapshot; no error is returned or logged.
- **Fastly tier set to "active" for `host_header_probe`:** The `host_header` technique is `TierActive`; if `baseOpts` used `TierPassive`, the technique would be skipped. `unearth_host_header_probe` explicitly sets `TierActive`.

---

## 12. Deviations

- **`detect_test.go` reference:** There's a `detect_test.go` file in `pkg/cdn` listed from earlier packet work. No changes were made to it in Packet 6.
- **Akamai not added:** Per spec §B.4 ("add a provider only if you can do it cleanly with good data and a detection signal you can verify"). Akamai's data is explicitly non-exhaustive per its maintainer.

---

## 13. Blockers

None.

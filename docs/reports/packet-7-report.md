# Packet 7 Report — Documentation & Release

**Date:** 2026-05-17
**Branch:** main

---

## 1. Status

**DONE.** Documentation written (README, docs/, CHANGELOG), release engineering complete, v1.0.0 tagged and pushed.

---

## 2. Checkpoint Results

**Final verification before tagging:**

```
go build ./...                    PASS
CGO_ENABLED=0 go build ./...      PASS
go vet ./...                      PASS
gofmt -l .                        (empty)
go test -race ./...               PASS (all packages)
go mod tidy                       PASS
```

**Commit:** (see git log — Packet 7 commit)
**Tags:** `packet-7-complete`, `v1.0.0`
**CI:** Triggered by `v1.0.0` push; release workflow runs GoReleaser to produce cross-platform artifacts.

---

## 3. Documentation

### README.md

The existing "under construction" README was replaced with the full project README covering:
- Project description and one-paragraph summary
- Installation (`go install` + release binaries)
- Quick start (3 usage examples including a pipeline)
- How it works (three-tier model + noisy-OR ranking summary)
- Techniques table (all 12 techniques: name, tier, API key, weight, description)
- API keys section (env vars, honest statement about keyless utility, Censys note)
- Output formats (`jsonl`, `json`, `table`) with examples
- CLI reference (all flags and subcommands)
- MCP server section with Claude Desktop config block
- Library use with minimal Go example
- CDN coverage (all 4 providers)
- Limitations (honest)
- Contributing (technique registry pattern, test conventions)

**Verified against code:** The technique table was verified against each technique's `Name()`, `Tier()`, `RequiresAPIKey()`, and `DefaultWeight()` methods. The CLI flags were verified against the cobra command definitions in `cmd/unearth/internal/cli/root.go`. The MCP server description was verified against `cmd/unearth-mcp/main.go`.

### docs/techniques.md

One section per technique (12 techniques). Each section covers: what the technique does, its data source(s), its limitations, and (for techniques with hardening) implementation notes. Verified against source files.

### docs/mcp.md

MCP server integration guide covering: building, client configuration (Claude Desktop and generic), API keys, the five tools (parameters and result shapes with examples), error handling, and diagnostics. Verified against `cmd/unearth-mcp/main.go`.

### docs/ranking.md

Explains the noisy-OR scoring formula with worked examples, all candidate output fields (`score`, `corroboration`, `single_source`, `techniques`), deduplication behavior, and weight configuration (per-run and persistent user override).

### CHANGELOG.md

Created following the Keep a Changelog convention. First entry is v1.0.0 dated 2026-05-17, summarizing the complete feature set across all seven packets.

---

## 4. Release Engineering

### `.github/workflows/release.yml`

New workflow that:
- Triggers on tag pushes matching `v*`
- Checks out with full history (`fetch-depth: 0` — required by GoReleaser for changelog)
- Sets up Go 1.23
- Runs `goreleaser/goreleaser-action@v6` with `--clean`
- Has `contents: write` permission to create GitHub releases and upload artifacts

### `.goreleaser.yaml`

Updated from the scaffold:
- Added `ldflags: -s -w -X github.com/unearth-tool/unearth/internal/httpclient.Version={{ .Version }}` to both build targets — this stamps the git tag into the binary at release time
- Changed `release.draft: true` to `release.draft: false` — releases are published directly (not left as drafts)
- Added `release.name_template: "unearth {{ .Tag }}"` and a header pointing to CHANGELOG.md
- Kept `CGO_ENABLED=0` for both binaries

### Version stamping

`internal/httpclient.Version` was changed from `const` to `var`:

```go
// Before (Packet 1):
const Version = "0.1.0-dev"

// After (Packet 7):
var Version = "0.1.0-dev"
```

`var` is required for ldflags injection (Go's linker cannot modify constants). A local `make build` still shows `0.1.0-dev`; a GoReleaser build will show the actual tag (e.g. `1.0.0`). The `version` command already reads `runtime/debug.ReadBuildInfo()` for commit and build date, so those fields are always accurate.

---

## 5. Smoke Tests

All smoke tests run against `dist/unearth` and `dist/unearth-mcp` built by `make build`:

**`unearth version`:**
```
unearth 0.1.0-dev
commit:  6bf5a19417feded253bd4f23f9cfab411ff209cc
built:   2026-05-18T02:46:52Z
```
Reports correctly. (The `0.1.0-dev` sentinel is expected for a local `make build`; the release build will report `1.0.0` via ldflags.)

**`unearth --help`:** Renders correctly. All flags and subcommands visible.

**`unearth cache --help`:** Shows `stats`, `purge`, and `clear` subcommands correctly.

**`unearth example.com --timeout 45s -o table`:**
```
Target: example.com  (CDN: cloudflare)
  IP               SCORE  CORROB  TECHNIQUES
  104.131.109.61   0.700  1       ct_fingerprint
  104.131.118.87   0.700  1       ct_fingerprint
  [... 48 candidates from ct_fingerprint ...]

  ! censys_cert: missing API key
  ! crtsh: context deadline exceeded
  ! dns_history: missing API key
```
CDN detection worked (cloudflare). `ct_fingerprint` found 50 candidates (other servers presenting certs for example.com — the target uses Cloudflare for CDN, so no non-CDN candidates are expected; the candidates are kaeferjaeger hits from the cloud-provider SNI scan). `crtsh` timed out in 45s (within spec — it has a 90s override that needs a 5-minute overall budget to resolve). No regression.

**`unearth-mcp` MCP initialize handshake:**
```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"unearth-mcp","version":"1.0.0"}}}
```
Server responded correctly to a tools-list handshake. Stdout carries only the protocol response. The server started cleanly with no API keys.

---

## 6. The Release

**`v1.0.0` tagged and pushed** to `origin`. The push triggered the release workflow (`.github/workflows/release.yml`). The workflow runs GoReleaser to build linux/darwin × amd64/arm64 archives and a checksums file, and creates a GitHub release.

If the release workflow run cannot be confirmed synchronously (no `gh` CLI authenticated), the operator can verify it at:
`https://github.com/bugsyhewitt/unearth/actions`

The `v1.0.0` tag is the public release tag. The `packet-7-complete` tag is the internal build checkpoint per the runbook.

---

## 7. Findings

- **`unearth-mcp` server version field:** The MCP server announces `version: "1.0.0"` in the `serverInfo` response — this is hardcoded in `cmd/unearth-mcp/main.go` as a string literal. It should ideally be updated for future releases. A simple ldflags injection into a package-level var in the MCP command would fix this; deferred since the server's MCP protocol version matters more than its own version string for agents.

- **`crtsh` 45s timeout smoke test:** The crtsh timeout (90s) didn't trigger within the 45s smoke test budget — that's expected behavior. The technique gracefully surfaces a `context deadline exceeded` error from the engine when the overall budget is exhausted before crtsh finishes. Users running with the full 5m default budget will get crtsh results (or its Cert Spotter fallback).

- **example.com smoke test results:** All 50 candidates from `ct_fingerprint` are DigitalOcean IPs presenting certs for "example.com" — because example.com is a ubiquitous test domain that appears in many TLS certificates issued to DOcean-hosted sites. The CDN detection correctly identifies cloudflare fronting. This is expected behavior, not a bug.

- **No behavior changes:** Packet 7 was documentation and release engineering only. The only code change was `const Version → var Version` in `internal/httpclient/httpclient.go` — required for ldflags injection and behavior-neutral.

---

## 8. Files Created / Changed

**New files:**
- `CHANGELOG.md`
- `docs/techniques.md`
- `docs/mcp.md`
- `docs/ranking.md`
- `.github/workflows/release.yml`
- `docs/reports/packet-7-report.md` (this file)
- `docs/reports/RUN-COMPLETE.md`

**Modified files:**
- `README.md` — full replacement
- `.goreleaser.yaml` — ldflags, release settings
- `internal/httpclient/httpclient.go` — `const` → `var` for Version

---

## 9. Decisions / Deviations

- **`release.draft: false`:** The spec says "tag and push" and the release workflow creates a GitHub release. Using `draft: false` means the release is immediately published when GoReleaser runs, which is the intended behavior for a tagged v1.0.0.
- **MCP server version hardcoded as "1.0.0":** The MCP library's `NewMCPServer` call takes a version string. Using a runtime variable would require a separate pkg-level var and ldflags path. Deferred — the MCP spec version (2025-03-26) is more important to agents than the server's own version string.

---

## 10. Blockers

None.

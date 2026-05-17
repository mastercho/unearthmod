# unearth

> Unearth the origin server behind any CDN.

`unearth` discovers the real origin IP hidden behind a CDN — Cloudflare,
CloudFront, and others — by running multiple recon techniques in parallel and
ranking candidate IPs by how many techniques independently agree

## 🚧 Status

**Under construction — v1.0 in progress.**

The repository currently contains the project scaffold: the core type
contracts, the technique registry, and the ranking engine. The techniques, the
CLI, and the MCP server are being built in sequence and are not yet usable.
This README will be expanded with installation and usage instructions once the
tool runs.

## Planned techniques

**Passive** — never contacts the target:

- Certificate transparency logs (crt.sh)
- DNS history (SecurityTrails / ViewDNS)
- SPF / MX record analysis
- Origin-style subdomain enumeration
- Censys certificate-fingerprint search

**Active** — direct requests to candidate IPs:

- Shodan certificate-fingerprint search
- HTTP host-header bypass
- Service banner grabbing

**Aggressive** — probes that provoke origin leaks:

- Error-page and misconfiguration probes
- IPv6 exposure probes

## How ranking works

Each technique carries a reliability weight. When several techniques surface
the same IP, their weights combine with a noisy-OR rule, so independent
agreement raises confidence without any single weak signal dominating the
result. Each candidate also reports how many techniques corroborated it, so a
lone hit is never mistaken for a confirmed one.

## Building

```sh
make build      # builds both binaries into ./dist
make test       # runs the test suite
make lint       # runs golangci-lint
```

Requires Go 1.23 or newer.

## License

MIT — see [LICENSE](LICENSE).


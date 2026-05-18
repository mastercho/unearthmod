# Ranking Engine

`unearth` uses a **noisy-OR** model to score candidate origin IPs. This document explains how it works, what the output fields mean, and how to configure technique weights.

---

## The problem

Any single recon technique can produce both false positives (CDN IPs that slipped through the filter) and false negatives (real origins the technique didn't find). The goal of the ranking engine is to:

1. Surface IPs that multiple independent techniques agree on — **corroboration raises confidence**.
2. Flag lone hits explicitly — independent of their score, a single-source IP deserves skepticism.
3. Let techniques with different reliabilities contribute proportionally to the final score.

---

## Noisy-OR scoring

The score for an IP is computed from the weights of the techniques that found it:

```
score = 1 − ∏ (1 − w_i)
       for each technique i that found this IP
```

This is the probability that at least one of the independent witnesses is correct, assuming each is independently unreliable with probability `(1 − w_i)`.

**Examples:**

| Techniques that agree | Weights | Score |
|---|---|---|
| Only `crtsh` (0.55) | 0.55 | 0.55 |
| `crtsh` + `spf_mx` | 0.55 + 0.50 | 0.7975 |
| `crtsh` + `spf_mx` + `ct_fingerprint` | 0.55 + 0.50 + 0.70 | 0.939 |
| `censys_cert` alone (0.90) | 0.90 | 0.90 |

**Key property:** adding another technique's evidence always increases the score. A 0.35-weight technique (`subdomain_enum`) still meaningfully boosts a candidate found by stronger techniques.

**Ceiling:** score approaches 1.0 as more techniques agree, but never reaches it — corroboration raises confidence, it doesn't establish proof.

---

## Output fields

Each candidate in the result has:

```json
{
  "candidate_ip": "93.184.216.34",
  "score": 0.939,
  "corroboration": 3,
  "single_source": false,
  "techniques": [
    {"name": "ct_fingerprint", "weight": 0.70, "evidence": "..."},
    {"name": "crtsh",          "weight": 0.55, "evidence": "..."},
    {"name": "spf_mx",         "weight": 0.50, "evidence": "..."}
  ]
}
```

**`score`** — the noisy-OR confidence in [0, 1]. Higher is more likely to be the real origin. A score above ~0.8 with corroboration ≥ 3 is a strong signal.

**`corroboration`** — the number of distinct techniques that found this IP. Use this alongside `score`: a `censys_cert`-only hit scores 0.90 (high score, corroboration 1) while a 3-technique agreement at 0.94 is more trustworthy because it's harder to fake.

**`single_source`** — true when exactly one technique found this IP, regardless of that technique's weight. It is a deliberate separate signal: a lone strong hit (`censys_cert` alone at 0.90) and a lone weak hit (`subdomain_enum` alone at 0.35) both get `single_source: true` so the consumer treats them with appropriate skepticism.

**`techniques`** — the list of contributing techniques with their individual weights and evidence strings. Use the evidence strings to understand *why* each technique found this IP.

---

## Candidate deduplication

IPs are deduplicated by address across all techniques. If `crtsh` and `ct_fingerprint` both find `93.184.216.34`, they contribute to the same candidate — their weights combine in the noisy-OR formula and both evidence strings appear in `techniques`.

---

## Technique weights

Default weights are embedded in the binary from `pkg/config/default-weights.yaml`. They reflect a subjective assessment of each technique's reliability based on observed false-positive rates in testing. See [docs/techniques.md](techniques.md) for per-technique weight justifications.

### Overriding weights

**Per-run override** via `--weights`:

```sh
cat > my-weights.yaml <<EOF
censys_cert: 0.95   # more confidence in your Censys tier
crtsh: 0.40         # less confidence if you've seen many false positives
EOF

unearth --weights my-weights.yaml example.com
```

**Persistent user override** — place a YAML file at:
- `$XDG_CONFIG_HOME/unearth/weights.yaml`, or
- `~/.config/unearth/weights.yaml`

The user file is loaded automatically and merged with the embedded defaults. Keys in the user file override the defaults; unspecified techniques retain their default weight.

**Format:** a flat YAML map of technique name to weight (float in [0, 1]):

```yaml
ct_fingerprint: 0.80
censys_cert: 0.95
crtsh: 0.40
```

Unknown technique names in the weight file produce a warning in `result.warnings` but are otherwise ignored.

---

## Candidates are sorted by score, descending

The `candidates` array in the result is sorted from highest to lowest score. The first candidate is the engine's best guess at the real origin IP. Use `--top N` to truncate the output to the N most confident candidates.

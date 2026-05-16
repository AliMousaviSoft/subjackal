# AGENTS.md — subjackal

## Project

Go CLI tool for subdomain takeover detection. Module: `github.com/AliMousaviSoft/subjackal`, Go 1.26.2.

## Build & Run

```bash
go build -o subjackal .
go install -v github.com/AliMousaviSoft/subjackal@latest
./subjackal --target example.com
```

## Package architecture (7 internal packages + cmd)

```
cmd/root.go          — CLI flags, pipeline wiring, result processing
internal/
  model/             — Subdomain, Status, Confidence, ConfidenceScore (core types)
  enum/              — Enumerator interface + crt.sh / file / stdin implementations
  resolve/           — DNS resolver pool, caching, wildcard detection, CNAME chaining
  analyze/           — Fingerprint matching (CNAME suffix + HTTP body), takeover analysis
  probe/             — HTTP body probing for confirmation
  pipeline/          — Fan-out concurrent pipeline: enumerate → resolve → analyze → probe
  output/            — Colored terminal output + JSON Lines writer
  validate/          — Deep validation (Wayback, CT log, DNS verification, provider checks)
```

## Pipeline flow

```
Enumerator (crt.sh / file / stdin)
  → DNS resolver (CNAME chain, A/AAAA/NS, NXDOMAIN detection)
  → Analyzer (fingerprint match → StatusSuspicious)
  → HTTP prober (body fingerprint → StatusVulnerable / downgrade to Alive)
  → Output (stdout / JSON file)
```

## Key CLI flags (beyond README)

| Flag | Note |
|------|------|
| `--http-timeout` | HTTP probe timeout, default 5000ms (separate from `--timeout`) |
| `--retries` | DNS query retry count, default 3 |
| `--no-http` | DNS-only mode, skips HTTP probing |
| `--cname-only` | Only process subdomains with CNAME records |
| `--verify` | Verify NXDOMAINs across multiple resolvers |
| `--validate` | Deep validation (Wayback, CT logs, provider checks) |
| `--fingerprints` | Custom fingerprints JSON file (merged with embedded) |
| `--match` | Only report specific services (e.g. `heroku,github`) |
| `--only` | Filter output: `vulnerable,suspicious,nxdomain,alive` |
| `--exclude` / `--include` | Pattern-based subdomain filter (substring match) |
| `--json` | JSON output to stdout (flag exists but is unused in code) |

## Non-obvious facts

- **Enumerator selection priority**: stdin > `--subs` file > crt.sh (default). If piped input is detected, --subs and --target are ignored.
- **`--debug`**: Enumeration-only test mode — prints subdomains and exits, skips all DNS/analysis.
- **Fingerprints are embedded**: `internal/analyze/fingerprints.json` via `//go:embed`. Custom file via `--fingerprints` uses merge strategy (custom entries win).
- **NXDOMAIN uses consensus**: queries up to 3 shuffled resolvers, requires >=2 to agree (reduces false positives).
- **Wildcard detection**: probes a random 12-hex subdomain before pipeline starts. Subdomains resolving to the wildcard IP are skipped.
- **Confidence scoring**: CNAME match (+70), NXDOMAIN back (+20), HTTP match (+100), NS unregistered (+150). Thresholds: >=120 High, >=50 Medium.
- **HTTP downgrade**: A 2xx/3xx response from a Suspicious subdomain downgrades it to Alive (not a takeover candidate).
- **`--up` runs `go install ...@latest`** — requires Go in PATH.
- **`configs/` directory** is empty, reserved for future use.
- **No tests exist** in the codebase. No CI workflows either.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, invoke the `skill` tool with `skill: "graphify"` before doing anything else.

Rules:
- ALWAYS read graphify-out/GRAPH_REPORT.md before reading any source files, running grep/glob searches, or answering codebase questions. The graph is your primary map of the codebase.
- IF graphify-out/wiki/index.md EXISTS, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

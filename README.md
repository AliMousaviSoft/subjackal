# subjackal

> Subdomain takeover hunter — fast, modular, pipeline-based

![Go](https://img.shields.io/badge/go-1.21+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Install

```bash
go install -v github.com/AliMousaviSoft/subjackal@latest
```

## Usage

```bash
# enumerate via crt.sh
subjackal --target example.com

# use pre-enumerated subdomains (recommended — more reliable)
subfinder -d example.com -o subs.txt
subjackal --subs subs.txt

# pipe directly from subfinder
subfinder -d example.com -silent | subjackal

# multiple targets from file
subjackal --targets domains.txt
 
# only show actionable findings
subjackal --subs subs.txt --only suspicious,vulnerable
 
# deep validate suspicious/vulnerable findings
subjackal --subs subs.txt --only suspicious,vulnerable --validate
 
# show dismissed candidates with reasons
subjackal --subs subs.txt --only suspicious,vulnerable --validate --verbose
 
# save results to JSON
subjackal --subs subs.txt -o results.json
 
# validate output also saved automatically
subjackal --subs subs.txt --validate -o results.json
# → results.json          (scan results)
# → results.json.validate.json  (validate reports)
 
# silent — only print vulnerable/suspicious, pipe-friendly
subjackal --subs subs.txt --silent | tee findings.txt
 
# DNS-only, skip HTTP probing (faster)
subjackal --subs subs.txt --no-http
 
# CNAME-only mode — focus on takeover candidates
subjackal --subs subs.txt --cname-only
 
# filter by pattern
subjackal --subs subs.txt --exclude qa,dev,staging
subjackal --subs subs.txt --include shop,admin
 
# filter by service
subjackal --subs subs.txt --match heroku,github,azure
 
# custom resolvers + threads + timeouts
subjackal --subs subs.txt \
  --resolvers 1.1.1.1:53,8.8.8.8:53 \
  --threads 100 \
  --timeout 2000 \
  --http-timeout 5000 \
  --retries 2
 
# self-update
subjackal --up
```
 
## Flags
 
| Flag | Default | Description |
|---|---|---|
| `--target` | — | Single target domain (uses crt.sh) |
| `--targets` | — | File with list of domains |
| `--subs` | — | File with pre-enumerated subdomains (skips crt.sh) |
| `--threads` | 50 | Concurrency |
| `--timeout` | 3000 | DNS timeout in ms |
| `--http-timeout` | 5000 | HTTP timeout in ms |
| `--retries` | 3 | DNS retry count |
| `--resolvers` | built-in | Custom DNS resolvers (comma-separated) |
| `-o` | — | Write JSON results to file |
| `--silent` | false | Suppress terminal output |
| `--only` | — | Filter output: `vulnerable,suspicious,nxdomain,alive,dismissed` |
| `--exclude` | — | Exclude subdomains matching patterns |
| `--include` | — | Only include subdomains matching patterns |
| `--match` | — | Only report specific services (e.g. `heroku,github`) |
| `--no-http` | false | Skip HTTP probing (DNS-only mode) |
| `--cname-only` | false | Only process subdomains with CNAME records |
| `--no-wildcard` | false | Disable wildcard detection |
| `--validate` | false | Deep validate suspicious/vulnerable findings |
| `--verbose` | false | Show dismissed candidates with reasons |
| `--inspect` | false | Show full DNS records for suspicious/vulnerable |
| `--fingerprints` | built-in | Custom fingerprints JSON file |
| `--debug` | false | Test enumeration only |
| `--up` | false | Self-update to latest version |
 
## Output
 
```
[VULNERABLE] wmvoicewidgetdev.example.com
             service    : Microsoft Azure [vulnerable]
             confidence : high (score: 190)
             note       : CONFIRMED — Microsoft Azure CNAME target NXDOMAIN
 
[VALIDATE] wmvoicewidgetdev.example.com
  │
  ├── CNAME chain
  │   → analytics-widget-dev.azurewebsites.net
  │   → final: analytics-widget-dev.azurewebsites.net (NXDOMAIN — dangling)
  │
  ├── Wayback check   : last seen 2024-03-12 (3 snapshots)
  ├── CT log check    : cert issued 2024-01-15 via Let's Encrypt (total: 4)
  ├── Verification DNS: no provider ownership lock
  ├── Provider HTTP   : RECLAIMABLE — 404 web site not found (HTTP 404)
  │
  ├── Score breakdown
  │   ├── +20 wayback: was indexed
  │   ├── +20 ct log: cert issued 2024-01-15 via Let's Encrypt
  │   ├── +30 verification: no provider ownership lock in DNS
  │   ├── +30 provider http: reclaimable
  │   └── +20 final target: NXDOMAIN confirmed — chain is genuinely dangling
  │
  └── Verdict         : HIGH — worth manual attempt (score: 100/100)
 
[SUSPICIOUS] sub.example.com — CNAME → Heroku (medium confidence, score: 90)
[ALIVE]      api.example.com
[NXDOMAIN]   old.example.com
[DISMISSED]  shop.example.com
             cname      : shops.myshopify.com.
             resolves to: 23.227.38.74
             reason     : CNAME chain resolves to live IP — not dangling
```
 
## Pipeline
 
```
crt.sh / file / stdin
        ↓
  Wildcard detection
        ↓
  DNS Resolver pool (miekg/dns)
  ├── CNAME chain walker (full depth)
  ├── Final hop A record resolution
  └── NS delegation check
        ↓
  Classifier
  ├── ALIVE      — chain resolves to live IP
  ├── DISMISSED  — had known CNAME but chain resolves
  ├── NXDOMAIN   — confirmed across multiple resolvers
  └── CNAME dangling → Analyzer
        ↓
  Fingerprint matcher (40+ services)
  └── Score: CNAME match (+70) + NXDOMAIN backend (+20)
        ↓
  HTTP prober (body fingerprint)
  └── Score: HTTP confirmed (+100) or live page → ALIVE
        ↓
  Validator (--validate flag)
  ├── Wayback Machine check
  ├── CT log history (crt.sh)
  ├── Provider-specific DNS ownership lock
  ├── Provider HTTP reclaimability check
  └── Verdict: HIGH / MEDIUM / LOW / NOISE
        ↓
  Output (stdout + JSON)
```
 
## Detection Logic
 
**Scoring system (max 190):**
 
| Signal | Points | Condition |
|---|---|---|
| CNAME match | +70 | CNAME points to known third-party service |
| NXDOMAIN backend | +20 | CNAME target itself is NXDOMAIN |
| HTTP confirmed | +100 | Body fingerprint matches takeover pattern |
| NS unregistered | +150 | NS delegation to unregistered domain |
 
**Validate scoring (max 100):**
 
| Signal | Points | Condition |
|---|---|---|
| Wayback hit | +20 | Domain was previously indexed |
| CT log cert | +20 | Certificate was previously issued |
| No ownership lock | +30 | No provider verification DNS record |
| HTTP reclaimable | +30 | Provider returns reclaimable error pattern |
| NXDOMAIN confirmed | +20 | Final CNAME hop is genuinely dangling |
| Resolves to IP | -50 | Chain is alive, not dangling |
 
## Fingerprints
 
40+ services from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz):
 
GitHub Pages, Heroku, AWS S3, AWS Elastic Beanstalk, Shopify, Fastly, Ghost,
Netlify, Vercel, Microsoft Azure, Zendesk, Tumblr, Surge.sh, Bitbucket,
WordPress, Discourse, JetBrains, Pantheon, Pingdom, Readme.io, Ngrok, and more.
 
Custom fingerprint file:
 
```bash
subjackal --subs subs.txt --fingerprints my-fingerprints.json
```
 
Format:
 
```json
{
  "services": [
    {
      "name": "My Service",
      "cname_patterns": [".myservice.io"],
      "http_fingerprint": "page not found on myservice",
      "status": "vulnerable",
      "takeover_possible": true
    }
  ]
}
```
 
## Status Types
 
| Status | Description |
|---|---|
| `VULNERABLE` | Confirmed takeover candidate — DNS + HTTP fingerprint match |
| `SUSPICIOUS` | CNAME to known service, NXDOMAIN backend — HTTP probe needed |
| `ALIVE` | Active service, not a takeover candidate |
| `NXDOMAIN` | Domain does not exist, no CNAME chain |
| `DISMISSED` | Had CNAME to known service but chain resolves to live IP |
 
## Workflow for Bug Bounty
 
```bash
# 1. enumerate
subfinder -d target.com -silent -o subs.txt
 
# 2. scan
subjackal --subs subs.txt --only suspicious,vulnerable -o scan.json
 
# 3. deep validate findings
subjackal --subs subs.txt --only suspicious,vulnerable --validate --verbose -o results.json
 
# 4. review HIGH verdict findings
cat results.json.validate.json | jq '.[] | select(.verdict_score >= 80)'
```
 
## Notes
 
- Uses `miekg/dns` directly — no system resolver dependency
- CNAME chains walked to full depth — multi-hop CDN chains handled correctly
- Wildcard detection prevents false positives on wildcard DNS zones
- HTTP probe only fires on CNAME-matched candidates — not on every subdomain
- Verification check uses provider-specific DNS records only (`asuid.`, `_vercel.`, etc.)
  not generic ACME challenge records which are present on nearly every domain

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

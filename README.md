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
# enumerate via crt.sh + analyze
subjackal --target example.com

# use pre-enumerated subdomains (e.g. from subfinder)
subfinder -d example.com -o subs.txt
subjackal --subs subs.txt

# multiple targets
subjackal --targets domains.txt

# save results to JSON
subjackal --subs subs.txt -o results.json

# silent mode — only print vulnerable/suspicious
subjackal --subs subs.txt --silent

# pipe-friendly
subjackal --subs subs.txt --silent | tee findings.txt

# custom resolvers + threads
subjackal --target example.com --resolvers 1.1.1.1:53,8.8.8.8:53 --threads 100

# self-update
subjackal --up
```

## Flags

| Flag | Description |
|---|---|
| `--target` | Single target domain |
| `--targets` | File with list of domains |
| `--subs` | File with pre-enumerated subdomains (skips crt.sh) |
| `--threads` | Concurrency (default 50) |
| `--timeout` | DNS timeout in ms (default 3000) |
| `-o` | Write JSON results to file |
| `--silent` | Suppress terminal output, only write to file |
| `--resolvers` | Custom DNS resolvers |
| `--up` | Self-update to latest version |
| `--debug` | Test enumeration only |

## Output

```
[VULNERABLE] sub.example.com
service    : Heroku
confidence : high
note       : CONFIRMED — Heroku fingerprint matched via HTTP

[SUSPICIOUS] sub.example.com
CNAME      → GitHub Pages
confidence : medium

[ALIVE]    api.example.com

[NXDOMAIN] old.example.com
```

---

## ⚙️ Pipeline

```
crt.sh / file
    ↓
Resolver (miekg/dns pool)
    ↓
CNAME chain walker + wildcard detection
    ↓
Analyzer (fingerprint match)
    ↓
HTTP prober (body fingerprinting)
    ↓
Output (stdout / JSON)
```

---

## 🔍 Detection Logic

- DNS Resolution
- CNAME Analysis
- Fingerprint Matching
- HTTP Probing

---

## 🧠 Fingerprints

Supports detection for 14+ services including:

- GitHub Pages  
- Heroku  
- AWS S3  
- Shopify  
- Fastly  
- Ghost  
- Netlify  
- Vercel  
- Azure  
- Zendesk  
- Tumblr  
- Surge.sh  

Based on:
https://github.com/EdOverflow/can-i-take-over-xyz

---

## 📤 Output Modes

- stdout (default)
- JSON

---

## 🚨 Status Types

| Status     | Description                |
|------------|----------------------------|
| VULNERABLE | Confirmed takeover         |
| SUSPICIOUS | Needs manual review        |
| ALIVE      | Active service             |
| NXDOMAIN   | Domain does not exist      |

---

## 📌 Notes

- HTTP fingerprinting reduces false positives
- Wildcard detection prevents noise
- Optimized for large-scale recon

---

## 🛠 Use Case

- Bug bounty hunters
- Red team recon
- Asset discovery pipelines

---
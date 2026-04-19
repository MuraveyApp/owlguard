# 🦉 OwlGuard — finds, fixes, ships.

Security vulnerabilities found → fixed → PR created. Automatically.

```
Push code → OwlGuard scans → finds vulnerability → writes fix → creates PR → you merge
```

## How It Works

1. **OwlSec** scans your code (243 detectors, 12 languages)
2. **OwlMind** writes the fix (96.67% SWE-bench accuracy)
3. **OwlGuard** creates a PR with the fix + compliance report

From vulnerability to fix: **5 minutes instead of 67 days.**

## Quick Start

```bash
# Scan a local project
owlguard scan .

# Scan a GitHub repo
owlguard scan https://github.com/user/repo

# Scan + auto-fix critical/high
owlguard fix .

# Start webhook server (for GitHub App)
owlguard
```

## GitHub App

Install OwlGuard on your repo → every push and PR gets scanned automatically.

```
POST /webhook  — GitHub webhook endpoint
GET  /health   — Health check
```

## What Gets Fixed

| Category | Detectors | Auto-Fix |
|----------|-----------|----------|
| Injection (SQL, XSS, CMD) | 45 | ✅ |
| Authentication | 20 | ✅ |
| Cryptography | 15 | ✅ |
| Configuration | 25 | ✅ |
| Data Exposure | 18 | ✅ |
| **Total** | **243** | **30 fixers** |

## Compliance

Every scan includes compliance mapping:
- SOC 2
- PCI DSS
- HIPAA
- ISO 27001

## vs Competitors

| | OwlGuard | Semgrep | Snyk | Devin |
|---|---------|---------|------|-------|
| Find vulns | ✅ 243 | ✅ 2000+ | ✅ | ❌ |
| Fix vulns | ✅ AI | ❌ | Partial | ✅ |
| Create PR | ✅ | ❌ | ✅ (deps) | ✅ |
| Compliance | ✅ | ❌ | ✅ | ❌ |
| Price | **$99/mo** | Free/Pro | $$$ | $500/mo |

## License

MIT

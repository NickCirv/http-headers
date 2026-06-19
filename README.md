<div align="center">

# http-headers

**Inspect HTTP response headers — security score, caching audit, CORS check — in one command**

[![License: MIT](https://img.shields.io/badge/License-MIT-green?labelColor=0B0A09)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?labelColor=0B0A09)](package.json)
[![Node](https://img.shields.io/badge/node-%3E%3D18-blue?labelColor=0B0A09)](package.json)

</div>

## Install

No global install needed:

```bash
npx github:NickCirv/http-headers <url>
```

Or install globally:

```bash
npm install -g github:NickCirv/http-headers
```

## Usage

```bash
# Show all response headers
npx github:NickCirv/http-headers https://example.com

# Full audit: security + caching + CORS
hheaders https://example.com --all

# Security score only (0–100)
hheaders https://api.example.com --security

# JSON output for scripting
hheaders https://example.com --all --format json

# Compare headers across two environments
hheaders https://staging.example.com --compare https://example.com

# Custom header (use env var reference — never hardcode secrets)
hheaders https://api.example.com --header "Authorization: $API_TOKEN"
```

| Flag | Description |
|------|-------------|
| `--security` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server header — scored 0–100 |
| `--caching` | Cache-Control, ETag, Expires, Vary, Age, CDN headers (Cloudflare, CloudFront) |
| `--cors` | Access-Control-Allow-Origin, credentials, methods, headers, preflight max-age |
| `--all` | All three audits at once |
| `--follow` | Follow redirects (default: show the redirect chain) |
| `--compare <url2>` | Side-by-side header diff between two URLs |
| `--format json` | Machine-readable JSON output |
| `--method <METHOD>` | HTTP method (default: GET) |
| `--header "K: V"` | Send a custom request header |

## What it does

`http-headers` fetches a URL's response headers using only Node.js built-ins — no dependencies, no shell exec — and renders a colour-coded table. The `--security` flag scores six common security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) on a 0–100 scale and explains exactly what's missing. The `--caching` flag surfaces Cache-Control strategy, TTL, ETag, and CDN cache signals. The `--compare` flag diffs headers from two URLs side by side, useful for staging-vs-production checks.

---
<sub>Zero dependencies · Node ≥18 · MIT · by <a href="https://github.com/NickCirv">NickCirv</a></sub>

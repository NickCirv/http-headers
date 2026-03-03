# http-headers

> Inspect HTTP headers. Security score, caching audit, CORS check. Zero dependencies.

```
  https://example.com
  Status: 200

  Response Headers
  ─────────────────────────────────────────────────────────
  content-type          text/html; charset=UTF-8
  cache-control         max-age=604800
  etag                  "3147526947"
  x-cache               HIT
  strict-transport-security  max-age=31536000

  Security Audit
  ─────────────────────────────────────────────────────────
  Score: 🟡 55/100

  ✔ HSTS                     max-age=31536000
  ✘ CSP                      Missing — add Content-Security-Policy header
  ✔ X-Frame-Options          SAMEORIGIN
  ✔ X-Content-Type-Options   nosniff
  ✘ Referrer-Policy          Missing
  ✘ Permissions-Policy       Missing
  ✔ Server Header            No version leaked
```

## Install

No install required:

```bash
npx http-headers <url>
```

Or install globally:

```bash
npm install -g http-headers
```

## Quick Start

```bash
# Inspect all headers
hheaders https://example.com

# Full audit (security + caching + CORS)
hheaders https://example.com --all

# Security score only
hheaders https://api.example.com --security

# JSON output for scripting
hheaders https://example.com --all --format json

# Compare two environments
hheaders https://staging.example.com --compare https://example.com

# Follow redirects
hheaders https://example.com --follow

# Custom headers (secrets via env vars — never hardcoded)
hheaders https://api.example.com --header "Authorization: $API_TOKEN"
```

## Audit Modes

| Flag | What it checks |
|------|----------------|
| `--security` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server header |
| `--caching` | Cache-Control, ETag, Expires, Vary, Age, CDN headers (CloudFront, Cloudflare, x-cache) |
| `--cors` | Access-Control-Allow-Origin, credentials, methods, headers, max-age |
| `--all` | All of the above |

## Security Score

Scored 0–100:

| Header | Points | Condition |
|--------|--------|-----------|
| HSTS | +20 | Present with max-age ≥ 1 year |
| CSP | +20 | Present and no wildcard/unsafe-inline |
| X-Frame-Options | +15 | DENY or SAMEORIGIN |
| X-Content-Type-Options | +15 | nosniff |
| Referrer-Policy | +10 | Any value set |
| Permissions-Policy | +10 | Any value set |
| Server header | +10 | No version number leaked |

Grades: 🔴 < 40 (critical) | 🟡 40–70 (needs work) | 🟢 > 70 (good)

## Options

```
--security          Audit security headers + score (0-100)
--caching           Audit Cache-Control, ETag, CDN headers
--cors              Check CORS headers
--all               Run all audits
--follow            Follow redirects (default: show redirect chain)
--format json       Output as JSON instead of table
--compare <url2>    Compare headers from two URLs side by side
--method <METHOD>   HTTP method (default: GET)
--header "K: V"     Send custom header (prefix value with $ENV_VAR for secrets)
```

## Redirect Handling

By default, `http-headers` shows the full redirect chain without following it. Use `--follow` to follow redirects and inspect the final destination headers.

## Security Note

When passing sensitive values like API keys or tokens, use environment variable references instead of hardcoding them:

```bash
# Good — value read from environment
hheaders https://api.example.com --header "Authorization: $MY_TOKEN"

# Also good — set env then run
MY_TOKEN=secret hheaders https://api.example.com --header "Authorization: $MY_TOKEN"
```

---

Built with Node.js · Zero dependencies · MIT License

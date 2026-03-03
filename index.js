#!/usr/bin/env node
import https from 'https';
import http from 'http';
import { URL } from 'url';

// ANSI color codes
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

const NO_COLOR = process.env.NO_COLOR || !process.stdout.isTTY;
const paint = (color, str) => NO_COLOR ? str : `${color}${str}${c.reset}`;

// Parse CLI args
function parseArgs(argv) {
  const args = { urls: [], flags: {}, headers: [], method: 'GET', format: 'table' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--security') args.flags.security = true;
    else if (arg === '--caching') args.flags.caching = true;
    else if (arg === '--cors') args.flags.cors = true;
    else if (arg === '--all') args.flags.all = true;
    else if (arg === '--follow') args.flags.follow = true;
    else if (arg === '--format') args.format = argv[++i] || 'table';
    else if (arg === '--method') args.method = (argv[++i] || 'GET').toUpperCase();
    else if (arg === '--compare') args.compare = argv[++i];
    else if (arg === '--header') {
      const h = argv[++i];
      if (h) args.headers.push(h);
    } else if (!arg.startsWith('--')) {
      args.urls.push(arg);
    }
  }
  return args;
}

// Resolve header value if it starts with $ (env var reference)
function resolveHeaderValue(val) {
  if (val && val.startsWith('$')) {
    const envKey = val.slice(1);
    return process.env[envKey] || '';
  }
  return val;
}

// Build custom headers object from --header args
function buildCustomHeaders(headerArgs) {
  const out = {};
  for (const h of headerArgs) {
    const idx = h.indexOf(':');
    if (idx === -1) continue;
    const key = h.slice(0, idx).trim();
    const val = resolveHeaderValue(h.slice(idx + 1).trim());
    out[key] = val;
  }
  return out;
}

// Make HTTP request (no exec, no shell — pure Node.js built-ins)
function fetchHeaders(rawUrl, { method = 'GET', customHeaders = {}, followRedirects = false, maxRedirects = 10 } = {}) {
  return new Promise((resolve, reject) => {
    const redirectChain = [];
    let redirectCount = 0;

    function doRequest(url) {
      let parsed;
      try {
        parsed = new URL(url);
      } catch {
        return reject(new Error(`Invalid URL: ${url}`));
      }

      const isHttps = parsed.protocol === 'https:';
      const lib = isHttps ? https : http;
      const port = parsed.port || (isHttps ? 443 : 80);

      const options = {
        hostname: parsed.hostname,
        port,
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          'User-Agent': 'http-headers-cli/1.0.0',
          'Accept': '*/*',
          ...customHeaders,
        },
      };

      const req = lib.request(options, (res) => {
        redirectChain.push({ url, status: res.statusCode, headers: res.headers });

        const isRedirect = [301, 302, 303, 307, 308].includes(res.statusCode);
        if (isRedirect && res.headers.location) {
          if (!followRedirects) {
            return resolve({ url, finalUrl: url, status: res.statusCode, headers: res.headers, redirectChain });
          }
          if (redirectCount >= maxRedirects) {
            return reject(new Error(`Too many redirects (max ${maxRedirects})`));
          }
          redirectCount++;
          const next = new URL(res.headers.location, url).href;
          res.resume();
          return doRequest(next);
        }

        // Drain body (we only care about headers)
        res.resume();
        res.on('end', () => {
          resolve({
            url,
            finalUrl: url,
            status: res.statusCode,
            headers: res.headers,
            redirectChain,
          });
        });
      });

      req.setTimeout(10000, () => {
        req.destroy(new Error('Request timed out after 10s'));
      });

      req.on('error', reject);
      req.end();
    }

    doRequest(rawUrl);
  });
}

// Security audit
function auditSecurity(headers) {
  const h = headers;
  let score = 0;
  const findings = [];

  // HSTS
  const hsts = h['strict-transport-security'];
  if (hsts) {
    const maxAge = parseInt((hsts.match(/max-age=(\d+)/i) || [])[1] || '0', 10);
    if (maxAge >= 31536000) { score += 20; findings.push({ pass: true, name: 'HSTS', detail: `max-age=${maxAge}` }); }
    else { score += 10; findings.push({ pass: true, name: 'HSTS', detail: `max-age=${maxAge} (recommend ≥31536000)` }); }
  } else {
    findings.push({ pass: false, name: 'HSTS', detail: 'Missing — add Strict-Transport-Security: max-age=31536000; includeSubDomains' });
  }

  // CSP
  const csp = h['content-security-policy'];
  if (csp) {
    const hasWildcard = csp.includes("'unsafe-inline'") || csp.includes('*');
    if (!hasWildcard) { score += 20; findings.push({ pass: true, name: 'CSP', detail: 'Present, no wildcards' }); }
    else { score += 8; findings.push({ pass: false, name: 'CSP', detail: "Present but contains 'unsafe-inline' or wildcard — tighten policy" }); }
  } else {
    findings.push({ pass: false, name: 'CSP', detail: "Missing — add Content-Security-Policy header" });
  }

  // X-Frame-Options
  const xfo = h['x-frame-options'];
  if (xfo && /deny|sameorigin/i.test(xfo)) {
    score += 15;
    findings.push({ pass: true, name: 'X-Frame-Options', detail: xfo });
  } else {
    findings.push({ pass: false, name: 'X-Frame-Options', detail: 'Missing or weak — set to DENY or SAMEORIGIN' });
  }

  // X-Content-Type-Options
  const xcto = h['x-content-type-options'];
  if (xcto && /nosniff/i.test(xcto)) {
    score += 15;
    findings.push({ pass: true, name: 'X-Content-Type-Options', detail: 'nosniff' });
  } else {
    findings.push({ pass: false, name: 'X-Content-Type-Options', detail: 'Missing — add: nosniff' });
  }

  // Referrer-Policy
  const rp = h['referrer-policy'];
  if (rp) {
    score += 10;
    findings.push({ pass: true, name: 'Referrer-Policy', detail: rp });
  } else {
    findings.push({ pass: false, name: 'Referrer-Policy', detail: 'Missing — add Referrer-Policy: strict-origin-when-cross-origin' });
  }

  // Permissions-Policy
  const pp = h['permissions-policy'];
  if (pp) {
    score += 10;
    findings.push({ pass: true, name: 'Permissions-Policy', detail: pp.slice(0, 60) + (pp.length > 60 ? '…' : '') });
  } else {
    findings.push({ pass: false, name: 'Permissions-Policy', detail: 'Missing — add Permissions-Policy to restrict browser features' });
  }

  // Server header leaking version
  const server = h['server'];
  if (!server || !/[\d.]/.test(server)) {
    score += 10;
    findings.push({ pass: true, name: 'Server Header', detail: server ? `"${server}" — no version leaked` : 'Not present' });
  } else {
    findings.push({ pass: false, name: 'Server Header', detail: `"${server}" — remove version information` });
  }

  return { score, findings };
}

// Caching audit
function auditCaching(headers) {
  const h = headers;
  const findings = [];

  const cc = h['cache-control'];
  if (cc) findings.push({ name: 'Cache-Control', value: cc });
  else findings.push({ name: 'Cache-Control', value: null, warn: 'Missing — explicitly define caching behavior' });

  const etag = h['etag'];
  if (etag) findings.push({ name: 'ETag', value: etag });
  else findings.push({ name: 'ETag', value: null, info: 'Not set — consider adding for cache validation' });

  const expires = h['expires'];
  if (expires) findings.push({ name: 'Expires', value: expires });

  const vary = h['vary'];
  if (vary) findings.push({ name: 'Vary', value: vary });

  const age = h['age'];
  if (age) findings.push({ name: 'Age', value: `${age}s (served from cache)` });

  const xCache = h['x-cache'] || h['cf-cache-status'] || h['x-amz-cf-id'];
  if (h['x-cache']) findings.push({ name: 'CDN (x-cache)', value: h['x-cache'] });
  if (h['cf-cache-status']) findings.push({ name: 'Cloudflare Cache', value: h['cf-cache-status'] });
  if (h['x-amz-cf-id']) findings.push({ name: 'CloudFront', value: 'Present (x-amz-cf-id detected)' });

  let ttl = null;
  if (cc) {
    const mAgeMatch = cc.match(/max-age=(\d+)/i);
    if (mAgeMatch) ttl = parseInt(mAgeMatch[1], 10);
  }
  if (!ttl && expires) {
    const exp = new Date(expires);
    if (!isNaN(exp)) ttl = Math.max(0, Math.round((exp - Date.now()) / 1000));
  }

  const strategy = cc
    ? (cc.includes('no-store') ? 'No caching' : cc.includes('no-cache') ? 'Revalidate always' : ttl ? `Cache ${ttl}s` : 'Custom')
    : 'Unspecified';

  return { findings, ttl, strategy };
}

// CORS audit
function auditCors(headers) {
  const h = headers;
  const findings = [];

  const acao = h['access-control-allow-origin'];
  if (acao) {
    findings.push({ name: 'Allow-Origin', value: acao, warn: acao === '*' ? 'Wildcard — any origin allowed' : null });
  } else {
    findings.push({ name: 'Allow-Origin', value: null, info: 'Not set (non-CORS endpoint or same-origin only)' });
  }

  const acac = h['access-control-allow-credentials'];
  if (acac) {
    findings.push({
      name: 'Allow-Credentials',
      value: acac,
      warn: acac === 'true' && acao === '*' ? 'DANGER: credentials=true with wildcard origin is invalid and insecure' : null
    });
  }

  const acam = h['access-control-allow-methods'];
  if (acam) findings.push({ name: 'Allow-Methods', value: acam });

  const acah = h['access-control-allow-headers'];
  if (acah) findings.push({ name: 'Allow-Headers', value: acah });

  const aceh = h['access-control-expose-headers'];
  if (aceh) findings.push({ name: 'Expose-Headers', value: aceh });

  const acma = h['access-control-max-age'];
  if (acma) findings.push({ name: 'Max-Age (preflight)', value: `${acma}s` });

  return { findings };
}

// Display helpers
function pad(str, len) {
  const s = String(str);
  return s.length >= len ? s : s + ' '.repeat(len - s.length);
}

function printHeaderTable(headers, title) {
  const entries = Object.entries(headers);
  if (!entries.length) { console.log('  (no headers)\n'); return; }

  const maxKey = Math.min(40, Math.max(...entries.map(([k]) => k.length)));
  const lineWidth = process.stdout.columns || 100;
  const valWidth = Math.max(20, lineWidth - maxKey - 7);

  if (title) console.log(paint(c.bold + c.cyan, `\n  ${title}`));
  console.log(paint(c.dim, `  ${'─'.repeat(maxKey + valWidth + 5)}`));

  for (const [key, val] of entries) {
    const kStr = pad(key, maxKey);
    const vStr = String(val).slice(0, valWidth);
    const kPaint = paint(c.cyan, kStr);
    const vPaint = paint(c.white, vStr);
    console.log(`  ${kPaint}  ${vPaint}`);
  }
  console.log();
}

function printSecurityReport(audit) {
  const { score, findings } = audit;
  const emoji = score >= 70 ? '🟢' : score >= 40 ? '🟡' : '🔴';
  const scoreColor = score >= 70 ? c.green : score >= 40 ? c.yellow : c.red;

  console.log(paint(c.bold + c.cyan, '\n  Security Audit'));
  console.log(paint(c.dim, `  ${'─'.repeat(50)}`));
  console.log(`  Score: ${emoji} ${paint(c.bold + scoreColor, String(score))}${paint(c.dim, '/100')}\n`);

  for (const f of findings) {
    const icon = f.pass ? paint(c.green, '✔') : paint(c.red, '✘');
    const name = paint(c.bold, pad(f.name, 28));
    const detail = f.pass ? paint(c.dim, f.detail) : paint(c.yellow, f.detail);
    console.log(`  ${icon} ${name} ${detail}`);
  }
  console.log();
}

function printCachingReport(audit) {
  const { findings, ttl, strategy } = audit;
  console.log(paint(c.bold + c.cyan, '\n  Caching Audit'));
  console.log(paint(c.dim, `  ${'─'.repeat(50)}`));
  console.log(`  Strategy: ${paint(c.bold, strategy)}${ttl ? paint(c.dim, `  (TTL: ${ttl}s)`) : ''}\n`);

  for (const f of findings) {
    if (f.value) {
      const icon = paint(c.green, '✔');
      const warn = f.warn ? paint(c.yellow, `  ⚠ ${f.warn}`) : '';
      console.log(`  ${icon} ${paint(c.bold, pad(f.name, 24))} ${paint(c.dim, f.value)}${warn}`);
    } else {
      const icon = f.warn ? paint(c.red, '✘') : paint(c.dim, '·');
      const msg = paint(c.dim, f.warn || f.info || '');
      console.log(`  ${icon} ${paint(c.bold, pad(f.name, 24))} ${msg}`);
    }
  }
  console.log();
}

function printCorsReport(audit) {
  const { findings } = audit;
  console.log(paint(c.bold + c.cyan, '\n  CORS Audit'));
  console.log(paint(c.dim, `  ${'─'.repeat(50)}`));

  for (const f of findings) {
    if (f.value) {
      const icon = f.warn ? paint(c.yellow, '⚠') : paint(c.green, '✔');
      const warn = f.warn ? `\n    ${paint(c.red, f.warn)}` : '';
      console.log(`  ${icon} ${paint(c.bold, pad(f.name, 24))} ${paint(c.dim, f.value)}${warn}`);
    } else {
      const icon = paint(c.dim, '·');
      const msg = paint(c.dim, f.warn || f.info || '');
      console.log(`  ${icon} ${paint(c.bold, pad(f.name, 24))} ${msg}`);
    }
  }
  console.log();
}

function printRedirectChain(chain) {
  if (chain.length <= 1) return;
  console.log(paint(c.bold + c.magenta, '\n  Redirect Chain'));
  console.log(paint(c.dim, `  ${'─'.repeat(50)}`));
  for (let i = 0; i < chain.length; i++) {
    const r = chain[i];
    const statusColor = r.status >= 400 ? c.red : r.status >= 300 ? c.yellow : c.green;
    const arrow = i < chain.length - 1 ? paint(c.dim, ' →') : '';
    console.log(`  ${paint(statusColor, String(r.status))} ${paint(c.cyan, r.url)}${arrow}`);
  }
  console.log();
}

function printCompare(res1, res2) {
  const h1 = res1.headers;
  const h2 = res2.headers;
  const allKeys = [...new Set([...Object.keys(h1), ...Object.keys(h2)])].sort();
  const lineWidth = process.stdout.columns || 120;
  const colW = Math.floor((lineWidth - 4) / 3);

  const u1 = paint(c.cyan, res1.url.slice(0, colW - 2));
  const u2 = paint(c.cyan, res2.url.slice(0, colW - 2));
  console.log(paint(c.bold + c.cyan, '\n  Header Comparison'));
  console.log(paint(c.dim, `  ${'─'.repeat(lineWidth - 2)}`));
  console.log(`  ${paint(c.bold, pad('Header', colW))} ${paint(c.bold, pad('URL 1', colW))} ${paint(c.bold, 'URL 2')}`);
  console.log(`  ${paint(c.dim, pad(res1.url.slice(0, colW - 2), colW))} ${paint(c.dim, res2.url.slice(0, colW - 2))}`);
  console.log(paint(c.dim, `  ${'─'.repeat(lineWidth - 2)}`));

  for (const key of allKeys) {
    const v1 = h1[key] ? String(h1[key]).slice(0, colW - 2) : '';
    const v2 = h2[key] ? String(h2[key]).slice(0, colW - 2) : '';
    const diff = v1 !== v2;
    const kStr = pad(key, colW);
    const v1Str = pad(v1 || paint(c.dim, '—'), colW);
    const v2Str = v2 || paint(c.dim, '—');
    const rowColor = diff ? c.yellow : '';
    console.log(`  ${paint(rowColor, kStr)} ${paint(rowColor, v1Str)} ${paint(rowColor, v2Str)}`);
  }
  console.log();
}

function outputJson(data) {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n');
}

function printUsage() {
  console.log(`
${paint(c.bold + c.cyan, 'http-headers')} — HTTP header inspector & security scorer

${paint(c.bold, 'Usage:')}
  hheaders <url> [options]

${paint(c.bold, 'Options:')}
  --security          Audit security headers + score (0-100)
  --caching           Audit Cache-Control, ETag, CDN headers
  --cors              Check CORS headers
  --all               Run all audits
  --follow            Follow redirects (default: show chain)
  --format json       Output as JSON instead of table
  --compare <url2>    Compare headers from two URLs
  --method <METHOD>   HTTP method (default: GET)
  --header "K: V"     Send custom header (use \$ENV_VAR for secrets)

${paint(c.bold, 'Examples:')}
  hheaders https://example.com
  hheaders https://example.com --all
  hheaders https://api.example.com --security --format json
  hheaders https://a.com --compare https://b.com
  hheaders https://api.example.com --header "Authorization: \$API_TOKEN"
`);
}

// Main
async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.urls.length) {
    printUsage();
    process.exit(0);
  }

  const customHeaders = buildCustomHeaders(args.headers);
  const url = args.urls[0];

  // Compare mode
  if (args.compare) {
    let res1, res2;
    try {
      [res1, res2] = await Promise.all([
        fetchHeaders(url, { method: args.method, customHeaders, followRedirects: args.flags.follow }),
        fetchHeaders(args.compare, { method: args.method, customHeaders, followRedirects: args.flags.follow }),
      ]);
    } catch (err) {
      console.error(paint(c.red, `Error: ${err.message}`));
      process.exit(1);
    }

    if (args.format === 'json') {
      outputJson({ url1: { url, status: res1.status, headers: res1.headers }, url2: { url: args.compare, status: res2.status, headers: res2.headers } });
      return;
    }
    printCompare(res1, res2);
    return;
  }

  // Single URL
  let result;
  try {
    result = await fetchHeaders(url, { method: args.method, customHeaders, followRedirects: args.flags.follow });
  } catch (err) {
    console.error(paint(c.red, `Error: ${err.message}`));
    process.exit(1);
  }

  const { status, headers, redirectChain } = result;
  const statusColor = status >= 400 ? c.red : status >= 300 ? c.yellow : c.green;

  const runAll = args.flags.all;
  const secAudit = (runAll || args.flags.security) ? auditSecurity(headers) : null;
  const cacheAudit = (runAll || args.flags.caching) ? auditCaching(headers) : null;
  const corsAudit = (runAll || args.flags.cors) ? auditCors(headers) : null;

  if (args.format === 'json') {
    const out = { url, status, headers };
    if (secAudit) out.security = secAudit;
    if (cacheAudit) out.caching = cacheAudit;
    if (corsAudit) out.cors = corsAudit;
    if (redirectChain.length > 1) out.redirectChain = redirectChain;
    outputJson(out);
    return;
  }

  // Table output
  console.log(`\n  ${paint(c.bold, url)}`);
  console.log(`  Status: ${paint(c.bold + statusColor, String(status))}\n`);

  if (redirectChain.length > 1) printRedirectChain(redirectChain);

  printHeaderTable(headers, 'Response Headers');

  if (secAudit) printSecurityReport(secAudit);
  if (cacheAudit) printCachingReport(cacheAudit);
  if (corsAudit) printCorsReport(corsAudit);
}

main().catch((err) => {
  console.error(paint(c.red, `Fatal: ${err.message}`));
  process.exit(1);
});

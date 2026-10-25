---
name: web-timing-attacks
description: "Server-side timing attacks for discovery and exploitation: finding hidden routes/params, detecting blind injection and scoped SSRF, username enumeration, and reliable timing with the single-packet technique. Based on Kettle's 'Listen to the whispers' (2024)."
domain: server-side
source: unified-research-2025
---

# web-timing-attacks

> Timing is a universal side channel: even without visible output, *how long* the server takes leaks state. This skill turns small, noisy time differences into reliable signals.

## 1. When to load
- A target gives no reflected output, no errors, and no obvious oracle (truly blind).
- You suspect hidden parameters, feature flags, server-side request routing, or a WAF/cache that behaves differently for "interesting" input.
- Classic payloads are filtered but behavior still differs.

## 2. Kill the noise first
Timing fails when jitter > signal. Fixes:
- Use the **single-packet attack** (HTTP/2, one TCP packet) to compare two requests with near-zero network jitter — compare *response ordering*, not wall-clock ms.
- Warm connections, pin to one back-end, repeat and take the minimum.
- Prefer **differential** timing: send payload A and payload B back-to-back and compare, instead of absolute thresholds.

## 3. Discovery uses
| Goal | Technique |
|---|---|
| **Hidden params** | Send `?param=value` where `param` is guessed; a param that is *parsed* (DB lookup, cache miss, extra backend call) is measurably slower. Scale with Param Miner + timing. |
| **Server-side injection (blind)** | Inject a payload that forces work only if interpreted: `sleep`, heavy regex (ReDoS), expensive SSTI/`#{7*7*...}`, nested JSON, `||pg_sleep(5)||`. Delay = injection. |
| **Scoped/blind SSRF** | Point the server at `http://127.0.0.1:closedport` (fast RST) vs `:openport` (slow) vs external host (DNS/connect latency) to map internal services without any response body. |
| **Username / account enumeration** | Valid user triggers password-hash verification (bcrypt/argon2 = slow); invalid returns fast. Measure login/reset timing. |
| **Cache / WAF fingerprint** | Cache hit (fast) vs miss (slow) reveals keying; WAF inspection adds latency on "bad" input. |
| **Reflected input reaching a 2nd system** | Payload that triggers a slow downstream call only when it reaches the backend. |

## 4. Example: blind SQLi confirmation by timing
```
GET /item?id=1                     -> ~40ms baseline
GET /item?id=1'||pg_sleep(3)||'    -> ~3040ms  => injection
GET /item?id=1'||pg_sleep(0)||'    -> ~40ms    => control
```
Always run a 0-delay control to prove the delay is payload-driven, not load.

## 5. Tooling
- **Turbo Intruder** with `Engine.BURP2` single-packet for A/B timing.
- **Burp** Repeater *Send group in parallel* → compare arrival order.
- `curl -w "%{time_total}\n" -o /dev/null -s` for quick manual checks; loop 20x, take min.

## 6. Reporting
Timing findings need rigor: show control vs payload, repeat counts, and the stable delta. Frame discovery findings (hidden admin param, internal SSRF surface) by the vuln they unlock, not the timing itself.

## 7. Related skills
`http-desync-single-packet-attack`, `race-condition`, `ssrf`, `performing-blind-ssrf-exploitation`, `sql-injection`.

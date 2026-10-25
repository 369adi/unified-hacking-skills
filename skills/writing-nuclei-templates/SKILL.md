---
name: writing-nuclei-templates
description: "Author custom Nuclei templates to scale bug bounty: HTTP/raw requests, matchers and extractors, the DSL, interactsh OOB (blind SSRF/RCE), fuzzing (nuclei -fuzz / fuzzing-templates), workflows, and turning a one-off finding into a reusable detector. Use to operationalize any vulnerability you found manually."
domain: tooling
source: unified-research-2025
---

# writing-nuclei-templates

> The force-multiplier skill: every manual finding should become a Nuclei template so you can re-check it across all your targets and catch regressions/variants. Templates are YAML.

## 1. When to load
- You found a bug manually and want to scan your whole scope for it.
- You want OOB detection (blind SSRF/RCE/SSTI) via `interactsh`.
- You want to fuzz parameters at scale.

## 2. Minimal template anatomy
```yaml
id: example-token-disclosure
info:
  name: API token disclosed in JS bundle
  author: you
  severity: high
  tags: exposure,token
http:
  - method: GET
    path:
      - "{{BaseURL}}/static/app.js"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "api[_-]?key['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9]{32,}"
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        regex:
          - "api[_-]?key['\"]?\\s*[:=]\\s*['\"]([A-Za-z0-9]{32,})"
```

## 3. Matchers & extractors (the core)
- **Matcher types:** `word`, `regex`, `status`, `size`, `binary`, `dsl`.
- `matchers-condition: and|or`; negate with `negative: true`; target with `part: body|header|interactsh_protocol|...`.
- **Extractors** pull values (tokens, versions, IDs) into output and into later requests.
- **DSL** is the power tool:
```yaml
      - type: dsl
        dsl:
          - 'contains(body, "root:x:0:0") && status_code == 200'
          - 'len(body) > 0 && regex("CVE-2024", body)'
```

## 4. Raw requests + multi-step (chaining / stateful)
```yaml
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"user":"admin","pass":"{{password}}"}
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        Cookie: session={{session}}
    extractors:
      - type: regex
        name: session
        internal: true
        part: header
        regex: ["session=([^;]+)"]
```
Raw mode preserves exact bytes → ideal for smuggling/injection PoCs.

## 5. Blind / OOB detection with interactsh
```yaml
    raw:
      - |
        GET /?url=http://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["dns","http"]
```
Confirms blind SSRF, blind RCE (`; curl {{interactsh-url}}`), blind SSTI, log4shell-style callbacks — no response body needed.

## 6. Fuzzing at scale
- Use the official `fuzzing-templates` repo and `nuclei -fuzz` / `-dast` mode.
- Define fuzzable positions with `{{...}}` and `fuzzing:` rules (`part: query`, `mode: single|multiple`, `type: replace|postfix`).
- Great for reflected XSS, SQLi, SSTI, open redirect across every parameter httpx/katana discovered.

## 7. Workflow into your pipeline
```
subfinder -d target.com | httpx | katana | nuclei -t ./my-templates/ -fuzz -interactsh-server <self> -o hits.txt
```
Validate templates with `nuclei -validate -t template.yaml`; keep a private repo of your signed, high-signal templates.

## 8. Related skills
`subdomain-takeover`, `ssrf`, `performing-blind-ssrf-exploitation`, `xss`, `recon-methodology`, `http-desync-single-packet-attack`.

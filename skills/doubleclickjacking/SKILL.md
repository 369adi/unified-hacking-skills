---
name: doubleclickjacking
description: "DoubleClickjacking (Paulos Yibelo, 2024/25): abuse the timing gap during a double-click to defeat X-Frame-Options, frame-busting, and SameSite protections, landing a click on a sensitive action (OAuth consent, account deletion, fund transfer). Use when classic clickjacking is blocked."
domain: client-side
source: unified-research-2025
---

# doubleclickjacking

> Classic clickjacking is largely dead thanks to `X-Frame-Options`, `frame-ancestors`, and `SameSite` cookies. **DoubleClickjacking** revives it by exploiting the window *between* the two clicks of a double-click. See also `clickjacking`.

## 1. When to load
- Target sets `X-Frame-Options: DENY` / `frame-ancestors 'none'` (so iframe overlay fails) but performs a sensitive action behind a button.
- SameSite=Lax/Strict blocks cross-site CSRF, but the action is reachable while the user is logged in.
- You can get a victim to double-click on your page (fake captcha, "double-click to continue", game).

## 2. Why it works
No iframe is used — so frame-busting headers don't apply. Instead:
1. Attacker page opens the **target window** (popup or redirect) on `mousedown`.
2. During the victim's double-click, the attacker **swaps/positions windows** so the *second* click (the `mouseup`/second `click`) lands on the target's sensitive button.
3. The victim's first click interacts with the attacker page; the second click is "donated" to the target.

Because it's a real top-level window receiving a genuine user gesture, it bypasses framing protections and satisfies user-activation requirements (OAuth popups, "Authorize", "Delete").

## 3. PoC skeleton
```html
<button id="bait">Double-click to verify you are human</button>
<script>
let win;
document.getElementById('bait').addEventListener('mousedown', () => {
  // open the sensitive target so the 2nd click lands on it
  win = window.open('https://target.com/oauth/authorize?client_id=ATTACKER&...', '_blank',
                    'width=500,height=600,left=200,top=100');
});
document.getElementById('bait').addEventListener('click', () => {
  // after first click, close/relocate our UI so the target's Authorize button
  // sits under the cursor for the second click of the double-click
  // (position the popup so its primary action aligns with the pointer)
});
</script>
```
Tune popup geometry so the target's primary action button is under the pointer for the second click. Yibelo's PoCs cover OAuth "Authorize", account deletion, and extension-permission grants.

## 4. High-value targets
- **OAuth/OIDC consent** → account/API takeover (donate the "Authorize" click).
- **Account/data deletion**, **email/password change confirm**.
- **Fund transfer / withdrawal confirm**.
- **Browser-extension permission prompts**, **one-click settings toggles**.

## 5. Detection / fix (report)
- Sensitive actions should require more than a single gesture: re-auth, typed confirmation, or a short delay before the action button is active (disable button for ~300ms after window focus).
- Don't rely solely on `X-Frame-Options`/`frame-ancestors` — they do nothing against window-swap attacks.
- Use `window.opener` checks and require a visible, intentional confirmation step.

## 6. Related skills
`clickjacking`, `oauth-oidc-misconfiguration`, `css-injection-exfiltration`, `csrf`.

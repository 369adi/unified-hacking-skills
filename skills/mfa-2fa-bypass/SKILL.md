---
name: mfa-2fa-bypass
description: "Systematic MFA/2FA/OTP bypass testing for bug bounty: response/status manipulation, flow-skipping, OTP brute force and rate-limit bypass, backup-code and remember-device abuse, race conditions, and password-reset MFA drop. Use when an app has a second authentication factor."
domain: auth
source: unified-research-2025
---

# mfa-2fa-bypass

> MFA is one of the most consistently broken controls in bug bounty because it bolts onto an existing login flow. Test the *flow*, not just the code.

## 1. When to load
Any app with TOTP, SMS/email OTP, push approval, WebAuthn/passkeys, or backup codes as a second step.

## 2. The checklist (run top to bottom)

### A. Flow / state bypass
- **Skip the step:** complete step 1 (password), then directly request a *post-MFA* endpoint (`/dashboard`, `/api/me`, the resource you'd see after MFA). If it works, MFA is cosmetic.
- **Force-browse the "verified" response:** intercept the MFA response; if it's `{"mfa":"required"}` / `302 /mfa`, try replaying the *successful* login response or changing `"success":false` → `true`, status `401/302` → `200`.
- **Session upgrade check:** is the pre-MFA session cookie already fully authenticated? Try using it on protected routes before entering the code.

### B. OTP brute force & rate-limit bypass
- 4–6 digit OTP with no/weak limits = brute forceable. Use Turbo Intruder.
- **Rate-limit bypasses:** rotate `X-Forwarded-For`/`X-Real-IP`, add nulls/newlines to the code, change casing, re-request a new code to reset the counter, or use the **single-packet attack** to fire many guesses before the limiter triggers (see `http-desync-single-packet-attack`).
- **No expiry / reuse:** old OTP still valid; same OTP works for multiple accounts.

### C. Response & parameter manipulation
- Empty/`null`/missing OTP field accepted.
- OTP of another account accepted (missing user binding → IDOR on verification).
- 2FA code leaked in the response body, headers, or a subsequent API call.

### D. Backup / recovery abuse
- Backup codes brute forceable or predictable.
- **Password reset drops MFA:** reset the password → is the session MFA-exempt afterward? Very common critical.
- Email-change or "trust this device" disables MFA without re-auth.

### E. Remember-device / token abuse
- `remember_device` cookie not bound to device/user → reuse across sessions/accounts.
- Predictable or signed-but-not-verified trust token.

### F. Race conditions
- Submit the correct code N times in parallel to bypass single-use enforcement, or race enable/verify to lock in attacker's TOTP seed.

### G. Enrollment / downgrade
- Attacker enrolls their own TOTP on victim's half-authenticated session.
- Downgrade from passkey/push to weaker SMS/email OTP, then attack that.

## 3. Example: status-code bypass
```
HTTP/1.1 401 Unauthorized         ->  change to
HTTP/1.1 200 OK
{"twoFactorRequired":true}        ->  {"twoFactorRequired":false}
```
Use Burp "Match & Replace" on the response to see if the client proceeds (confirms a client-side-only gate; then prove it server-side).

## 4. Impact / reporting
Full MFA bypass = account takeover (critical). Partial (brute force with weak limit) = high. Always demonstrate end-to-end login as the victim, and state whether SMS/TOTP/passkey.

## 5. Related skills
`authentication-bypass`, `jwt-attacks`, `race-condition`, `http-desync-single-packet-attack`, `oauth-oidc-misconfiguration`.

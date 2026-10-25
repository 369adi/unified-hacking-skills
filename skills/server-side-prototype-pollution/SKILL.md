---
name: server-side-prototype-pollution
description: "Detect and exploit Server-Side Prototype Pollution (SSPP) in Node.js/JavaScript back-ends: non-destructive detection, property-reflection and status-code oracles, and gadget chains to RCE, DoS, and auth bypass. Distinct from client-side prototype-pollution."
domain: server-side
source: unified-research-2025
---

# server-side-prototype-pollution

> Based on PortSwigger's SSPP research. Unlike client-side prototype pollution (DOM), SSPP pollutes `Object.prototype` *on the server*, affecting every object the app creates — leading to RCE, DoS, or privilege escalation. See also `prototype-pollution` (client-side).

## 1. When to load
- A Node.js/Express/Nest/etc. back-end merges user JSON into objects (`Object.assign`, `_.merge`, `_.defaultsDeep`, custom deep-merge, query-string parsers).
- Endpoints accept nested JSON or `a[b][c]=d` style params.

## 2. Non-destructive detection (do NOT break the server)
Prefer techniques that are automatically scoped/reversible. PortSwigger's safe probes:
- **`__proto__` with a harmless property that the server reflects back.** Send:
```json
{"__proto__":{"json spaces":10}}
```
  Express uses `app.set('json spaces')` internally; after pollution, JSON responses become pretty-printed (extra whitespace) → visible, reversible oracle.
- **Status-code oracle:** pollute a property Node checks during HTTP parsing, e.g.:
```json
{"__proto__":{"status":510}}
```
  then watch for responses whose status changes to 510 / 400.
- **`content-type` / charset pollution** causing a predictable response change.
Always send a clean request afterward (or use a property that self-clears) and verify the app recovered.

## 3. Detection workflow
1. Find a sink: any endpoint merging user input (registration, profile update, settings, GraphQL variables, bulk import).
2. Send `__proto__`, `constructor.prototype`, and `constructor[prototype]` variants — some parsers block one but not another.
3. Use the json-spaces or status oracle to confirm pollution without a destructive gadget.
4. Use the **Burp "Server-Side Prototype Pollution Scanner"** extension to automate safe detection.

## 4. Exploitation gadgets
| Impact | Gadget idea |
|---|---|
| **RCE** | Pollute `NODE_OPTIONS`, `shell`/`argv0`/`env` options used by `child_process.spawn`/`exec`/`fork`; or pollute template-engine options to inject a template → SSTI → RCE |
| **RCE (spawn)** | `{"__proto__":{"argv0":"node","shell":"/proc/self/exe","NODE_OPTIONS":"--require /proc/self/environ"}}` then trigger a child process; smuggle JS via an env var you control |
| **DoS** | Pollute a property that breaks all object operations (e.g. make every object claim a bogus method) → app-wide 500 |
| **Privilege escalation** | Pollute `isAdmin`/`role` defaults so every new user object inherits elevated rights |
| **Reflected/stored XSS** | Pollute options controlling HTML escaping in a template engine |

## 5. Example chain (EJS/Handlebars SSTI via SSPP)
1. Confirm SSPP via json-spaces oracle.
2. Pollute the template engine's compile option (`outputFunctionName`, `escapeFunction`, etc.).
3. Render any page using that engine → injected JS executes server-side → RCE.

## 6. Fix guidance (report)
- `Object.freeze(Object.prototype)`; use `Map`/null-prototype objects for user data.
- Reject keys `__proto__`, `constructor`, `prototype` in recursive merge.
- Use `JSON.parse` reviver or schema validation (ajv with `additionalProperties:false`).

## 7. Related skills
`prototype-pollution`, `deserialization-insecure`, `testing-for-nodejs-vulnerabilities`, `ssti`.

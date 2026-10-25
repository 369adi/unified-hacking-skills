# MCP Research Brief (Agentic-Bug-Hunter)

Researched 2026-09-17 from official sources. For implementing `mcp/bughunter-mcp/`.

## Protocol

- **Stable revision:** `2026-07-28` — https://modelcontextprotocol.io/specification/2026-07-28
- **Modern:** no session handshake; version/capabilities in `_meta`
- **Legacy:** `2025-11-25` and earlier — `initialize` / `initialized`
- **Dual-era:** speak both (Python SDK v2 default)

## Transport

Prefer **stdio** for Cursor / Claude Code / Codex / OpenCode:

- Newline-delimited JSON-RPC on stdin/stdout
- **Never** write non-MCP text to stdout (log to stderr)
- Cancel: `notifications/cancelled` with `requestId`
- Spec: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio

## Python SDK

| Item | Current |
|---|---|
| Package | [`mcp`](https://pypi.org/project/mcp/) (v2.x) |
| Class | `from mcp.server import MCPServer` |
| **Do not use** | `FastMCP` (removed in v2) |
| Docs | https://py.sdk.modelcontextprotocol.io/ |

```python
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

mcp = MCPServer("Agentic-Bug-Hunter")

@mcp.tool(
    title="Example",
    annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
)
def example(query: str) -> str:
    """Search local hunt memory."""
    return f"results for {query}"
```

## Primitives

| Primitive | Methods |
|---|---|
| Tools | `tools/list`, `tools/call` |
| Resources | `resources/list`, `resources/read` |
| Prompts | `prompts/list`, `prompts/get` |

Structured output: return type → `outputSchema` + `structuredContent`. Tool errors should use `isError: true` with actionable content.

## Annotations (UX hints only — not a security boundary)

| JSON | Meaning |
|---|---|
| `readOnlyHint` | No environment mutation |
| `destructiveHint` | May delete/overwrite |
| `idempotentHint` | Repeat calls safe |
| `openWorldHint` | Touches external world |

Server-side policy must still enforce scope/approval.

## Long-running work

Tasks are an **extension** (`io.modelcontextprotocol/tasks`), not core. Check client capabilities; fall back to sync tools + progress. Cancel long tasks via `tasks/cancel` when the extension is negotiated.

## Client notes

| Host | Notes |
|---|---|
| Cursor | stdio; often legacy `initialize` — dual-era SDK required |
| Claude Code | stdio default |
| Codex | stdio |
| OpenCode | stdio (+ HTTP/SSE in some setups) |

## Repo findings (inspection)

- No native BugHunter MCP server yet — only Burp/Caido **client configs** and HackerOne **CLI/API** (not MCP protocol).
- Add `mcp/bughunter-mcp/` as sibling; do not replace existing integrations.
- Active tools must wrap `ScopeChecker` + `AutopilotGuard` (agent path), not raw `engine.py`/`hunt.py`.
- Discovered hosts ≠ authorized; RateLimiter exists but is not called from `check_request` today.

## Anti-patterns

- FastMCP tutorials
- Modern-only servers without dual-era
- `print()` to stdout under stdio
- Trusting annotations for authorization
- Assuming Tasks are universally available

## URLs

- Spec: https://modelcontextprotocol.io/specification/2026-07-28
- Tools: https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- Cancellation: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation
- Tasks: https://modelcontextprotocol.io/extensions/tasks/overview
- Schema: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts
- Python SDK: https://py.sdk.modelcontextprotocol.io/
- What’s new: https://py.sdk.modelcontextprotocol.io/whats-new/

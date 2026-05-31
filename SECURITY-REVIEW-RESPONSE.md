# Security Review Response — cronometer-api-mcp

**Status:** Review complete. This document responds to the DRAFT `SECURITY-REVIEW.md` prepared by Opus 4.8. The original plan is strong and should be implemented as-is, with the additions below folded in before or during implementation.

**Reviewer:** Claude (Opus 4.6), reviewing the full repomix codebase against the audit.

**Scope:** Everything in the repo — `server.py`, `client.py`, `Dockerfile`, CI workflows, `pyproject.toml`, `README.md`, `.env.example`, `server.json`. The original audit scoped to `server.py` + env/docs; this response extends the surface where warranted.

---

## 1. Verdict on the original plan

The original SECURITY-REVIEW.md is comprehensive for its stated scope. All seven findings (§3.1–§3.7) are accurate, correctly severity-ranked, and the proposed remediation (§6 Steps 0–8, §7 code changes) is ready to implement. The verification plan (§8) is thorough. No changes needed to any of the existing findings or proposed code.

**Implement the original plan as written**, then layer in the additions below.

---

## 2. Decisions on §10

These are the five decision points the original audit left for the reviewer:

1. **Separate `MCP_APPROVE_SECRET` from `MCP_AUTH_TOKEN`** — **Confirmed.** Correct separation of browser-form-exposure risk vs. header-only risk, consistent with the Basecamp fix.

2. **Fail-closed for remote transports (§3.2 / Step 3)** — **Confirmed.** Remove the unauthenticated fallback entirely. It's a foot-gun.

3. **`X-Forwarded-For` last-entry parsing for Railway** — **Confirmed.** Railway uses a single-hop edge proxy, so last-entry is correct. Add an explicit code comment documenting the one-hop assumption, and note that if the server ever moves behind a multi-hop chain (e.g., Cloudflare → Railway), the index needs adjustment.

4. **Scope limited to `server.py` + env/docs, `client.py` and tools untouched** — **Confirmed with exceptions.** Two `client.py` bugs should be fixed as drive-bys (see §3 ADD-8 below), and the Dockerfile deployment path needs attention (see §3 ADD-1). Tool definitions are fine as-is.

5. **DNS-rebinding protection (§3.7) — now or defer?** — **Defer.** The approve-secret gate is the higher-priority fix. Re-enable DNS-rebinding protection after the auth hardening is deployed and verified stable.

---

## 3. Additional findings (not in the original audit)

These are ordered by priority. The implementing agent should fold these into the remediation plan alongside the original Steps 0–8.

---

### ADD-1: HIGH — Docker/supergateway deployment path is completely unauthenticated

**This is the biggest gap in the original audit.**

The Dockerfile entrypoint runs:

```
exec supergateway \
  --stdio 'cronometer-api-mcp' \
  --outputTransport streamableHttp \
  --stateful \
  --streamableHttpPath /mcp \
  ...
```

When deployed via Docker, `main()` runs in **stdio mode** — which means it never enters the `sse`/`streamable-http` branch, the `OAuthAuthorizationMiddleware` is never applied, and supergateway proxies raw MCP calls with **zero authentication**. Anyone who can reach the container can call every tool.

The Docker image is published to GHCR on every push to `main` and on every release (`docker.yml`). This is the image anyone pulling from the container registry would use. The fail-closed fix in Step 3 only protects the native remote transport path — it does nothing for the Docker path.

**Remediation options (pick one):**

- **Option A (recommended):** Add auth documentation to the Dockerfile/README stating that the Docker image is intended for use behind an authenticating reverse proxy (e.g., Caddy with basicauth, Cloudflare Access, Tailscale). Add a prominent `## Security Warning` section to the README's Docker deployment instructions.
- **Option B:** Change the Dockerfile to run `cronometer-api-mcp` in native `streamable-http` mode (bypassing supergateway), which would engage the OAuth middleware. This changes the deployment architecture.
- **Option C:** Add supergateway-level auth (if supergateway supports it — check its docs for `--auth` or similar flags).

At minimum, Option A is required. The implementing agent should add the warning regardless of which option is chosen.

**Proposed README addition (for Option A):**

```markdown
### ⚠️ Docker Security

The Docker image exposes MCP tools via supergateway with **no built-in authentication**.
It is designed to run behind an authenticating reverse proxy or within a private network.

**Do NOT expose the Docker container directly to the public internet.**

If you need authenticated remote access, deploy using the native transport
(`MCP_TRANSPORT=streamable-http`) with `MCP_AUTH_TOKEN` and `MCP_APPROVE_SECRET`,
or place the Docker container behind an auth proxy (Caddy basicauth, Cloudflare
Access, Tailscale, etc.).
```

---

### ADD-2: MEDIUM — `_read_body` has no size limit (memory exhaustion DoS)

The `_read_body` static method reads the entire request body into memory with no cap:

```python
@staticmethod
async def _read_body(receive) -> bytes:
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    return body
```

An attacker can POST a multi-GB body to `/authorize`, `/token`, or `/register` and exhaust server memory. All three endpoints call `_read_body`.

**Remediation:** Add a size cap and return 413 if exceeded. 64KB is generous for OAuth form bodies.

**Proposed code change:**

```python
MAX_BODY_BYTES = 64 * 1024  # 64 KB — generous for OAuth form posts

@staticmethod
async def _read_body(receive) -> bytes:
    """Read the full request body from ASGI receive, with size limit."""
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("Request body too large")
        if not message.get("more_body", False):
            break
    return body
```

Then in each handler that calls `_read_body`, catch `ValueError` and return a 413:

```python
try:
    body = await self._read_body(receive)
except ValueError:
    from starlette.responses import Response
    await Response("Request body too large", status_code=413)(scope, receive, send)
    return
```

Add `MAX_BODY_BYTES` as a module-level constant alongside `CODE_TTL_S`, `MAX_AUTH_ATTEMPTS`, and `AUTH_WINDOW_S`.

---

### ADD-3: MEDIUM — `_pending_codes` and `_auth_attempts` grow unboundedly

The original audit proposes TTL on codes (Step 4) and a per-IP rate-limit dict (Step 6), but neither dict is ever pruned of expired entries:

- **`_pending_codes`:** Expired codes (past `CODE_TTL_S`) sit in the dict until consumed or process restart. Under sustained attack, an attacker who knows the approve-secret could fill memory with pending codes.
- **`_auth_attempts`:** Entries past their `reset_at` window are never removed. Under distributed attack from many IPs, this dict grows without bound.

**Remediation:** Add lazy eviction. On each request that touches either dict, sweep entries that are past their expiry. Add a hard cap on dict size as a backstop.

**Proposed code — add a cleanup method to the middleware class:**

```python
MAX_PENDING_CODES = 100
MAX_AUTH_ATTEMPT_ENTRIES = 10_000

def _cleanup_expired(self):
    """Lazy eviction of expired pending codes and stale rate-limit entries."""
    now = time.monotonic()

    # Evict expired auth codes
    expired_codes = [
        code for code, meta in self._pending_codes.items()
        if now - meta.get("created_at", 0) > CODE_TTL_S
    ]
    for code in expired_codes:
        self._pending_codes.pop(code, None)

    # Evict expired rate-limit entries
    expired_ips = [
        ip for ip, entry in self._auth_attempts.items()
        if now > entry["reset_at"]
    ]
    for ip in expired_ips:
        self._auth_attempts.pop(ip, None)
```

Call `self._cleanup_expired()` at the top of `_handle_authorize_submit` and `_handle_token`.

Additionally, in `_handle_authorize_submit`, after the approve-secret passes but before storing the code, check the dict size:

```python
if len(self._pending_codes) >= MAX_PENDING_CODES:
    self._cleanup_expired()  # try once more
    if len(self._pending_codes) >= MAX_PENDING_CODES:
        await JSONResponse(
            {"error": "server_error", "error_description": "Too many pending authorizations"},
            status_code=503,
        )(scope, receive, send)
        return
```

---

### ADD-4: LOW — `_html_escape` omits single-quote; use `html.escape` from stdlib

The proposed custom `_html_escape` function handles `&`, `<`, `>`, `"` but not `'` (single quote). The proposed HTML template uses double-quoted attributes, so this is safe *for this specific template*, but it's fragile — any future template edit using single-quoted attributes would reopen the vector.

Python's standard library has `html.escape(s, quote=True)` which handles all five characters and is battle-tested.

**Remediation:** Replace the custom function with the stdlib:

```python
from html import escape as _html_escape
```

Then use `_html_escape(value)` everywhere (it escapes `&`, `<`, `>`, `"`, `'` by default). Drop the custom `_html_escape` function entirely.

---

### ADD-5: LOW — `/register` leaks `client_id` and `client_secret` to any anonymous caller

Post-fix, the approve-secret gates code issuance, so leaking client credentials via `/register` isn't directly exploitable for token minting. But the endpoint still hands `self.client_id` and `self.client_secret` to any unauthenticated POST request. These credentials might be reused elsewhere, and leaking them is unnecessary exposure.

**Remediation (pick one):**

- **Option A (minimal):** Stop echoing back `client_secret` in the `/register` response. Change the response to return `"client_secret_expires_at": 0` (per RFC 7591, indicating a non-expiring secret that was already known to the client) instead of the actual secret value.
- **Option B:** Rate-limit `/register` the same way `/authorize` is rate-limited.
- **Option C:** Gate `/register` behind the approve-secret (strictest, but may break the Claude connector flow if it expects unauthenticated registration).

**Recommended: Option A.** Least risk of breaking the connector flow.

```python
async def _handle_register(self, scope, receive, send):
    # ... existing body parsing ...
    response = JSONResponse(
        {
            "client_id": self.client_id,
            "client_secret_expires_at": 0,   # secret known to client, not echoed
            "client_name": data.get("client_name", "mcp-client"),
            "redirect_uris": data.get("redirect_uris", []),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        },
        status_code=201,
    )
    await response(scope, receive, send)
```

**Important caveat:** Test this change against the Claude connector flow before shipping. If Claude's connector expects `client_secret` in the registration response to complete the OAuth handshake, this change will break the flow. In that case, fall back to Option B (rate-limit only).

---

### ADD-6: LOW — No `redirect_uri` validation (open redirect with code in URL)

`_handle_authorize_submit` accepts any `redirect_uri` and redirects to it with the auth code appended as a query parameter. Post-fix, the approve-secret gates this, but if someone obtains the approve-secret (shoulder-surfing, log leak, shared credentials), they could set `redirect_uri` to an attacker-controlled domain.

PKCE prevents the attacker from exchanging the code without the verifier, but the code still appears in:
- The attacker's server access logs
- Browser history
- Potentially `Referer` headers on the redirect target

**Remediation:** Validate `redirect_uri` against the value provided during `/register`, or against a hardcoded allowlist. For a single-user server, the simplest approach is to accept only URIs matching known Claude connector callback patterns.

**This is a "nice to have" given PKCE protection. Implement if time permits; do not block the main fix on this.**

---

### ADD-7: LOW — Cronometer session token partially logged

`client.py` lines 118–120 log the first 8 characters of the Cronometer session token:

```python
logger.info(
    "Cronometer login successful (userId=%d, token=%s...)",
    self._user_id,
    self._token[:8] if self._token else "???",
)
```

If logs are accessible (Railway log viewer, log aggregation), this leaks partial token material that could aid targeted attacks.

**Remediation:** Log the token length or a hash instead of a prefix:

```python
logger.info(
    "Cronometer login successful (userId=%d, token_len=%d)",
    self._user_id,
    len(self._token) if self._token else 0,
)
```

---

### ADD-8: INFO — `copy_day` and `get_fasting_with_date_range` bypass the timezone fix

In `client.py`, two methods use bare `date.today()` instead of `self._local_today()`:

- `copy_day` (line 547): `to_day = to_day or date.today()`
- `get_fasting_with_date_range` (line 669): `end = end or date.today()`

These bypass the `CRONOMETER_TIMEZONE` setting and use the server's system timezone (UTC on Railway). This isn't a security vulnerability, but it's a data integrity bug — these methods will operate on the wrong day when called near midnight Pacific time.

**Remediation:** Replace both with `self._local_today()`:

```python
# In copy_day:
to_day = to_day or self._local_today()

# In get_fasting_with_date_range:
end = end or self._local_today()
```

This is a drive-by fix — small, safe, and corrects a known regression.

---

### ADD-9: INFO — No dependency security scanning in CI

`ci.yml` runs ruff lint and format checks only. There is no `pip-audit`, `safety`, or similar tool checking for known vulnerabilities in dependencies (`httpx`, `uvicorn`, `mcp`, `python-dotenv`, `tzdata`).

Given this server holds Cronometer account credentials, a compromised dependency is a credential theft vector.

**Remediation:** Add `pip-audit` to the CI pipeline:

```yaml
# In .github/workflows/ci.yml, add a job:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v4
      - name: Install dependencies
        run: uv sync
      - name: Audit dependencies
        run: uv run pip-audit
```

Add `pip-audit` to the `[dependency-groups] dev` list in `pyproject.toml`:

```toml
[dependency-groups]
dev = [
    "ruff>=0.8.0",
    "pip-audit>=2.7.0",
]
```

---

### ADD-10: INFO — `MCP_BASE_URL` defaults to `http://` with no HTTPS warning

```python
base_url = os.getenv("MCP_BASE_URL", f"http://localhost:{port}")
```

The OAuth metadata endpoints will advertise HTTP URLs if `MCP_BASE_URL` isn't set or is set to an `http://` URL. In production behind Railway's edge, the actual connection is HTTPS (Railway terminates TLS), but the metadata will claim HTTP, which could confuse OAuth clients.

**Remediation:** In the fail-closed startup check (Step 3 / §7h), add a warning if `MCP_BASE_URL` doesn't start with `https://`:

```python
if not base_url.startswith("https://"):
    logger.warning(
        "MCP_BASE_URL does not use HTTPS (%s). "
        "OAuth metadata will advertise insecure endpoints. "
        "Set MCP_BASE_URL to your public HTTPS URL for production.",
        base_url,
    )
```

Don't hard-fail on this (it would break local dev), but warn loudly.

---

## 4. Updated remediation order

The original Steps 0–8 remain in their original order and priority. The additions slot in as follows:

| Priority | Step | Source | Summary |
|----------|------|--------|---------|
| **Immediate** | Step 0 | Original | Rotate `MCP_AUTH_TOKEN`; change Cronometer password if exposed |
| **Critical** | Steps 1–3 | Original | Approve-secret gate, fail-closed, core auth fix |
| **High** | Step 4 | Original | Auth-code TTL |
| **High** | ADD-1 | New | Docker deployment auth warning / remediation |
| **High** | ADD-2 | New | `_read_body` size limit |
| **Medium** | Step 5 | Original | Constant-time comparisons |
| **Medium** | Step 6 | Original | Per-IP rate limiting |
| **Medium** | ADD-3 | New | Dict cleanup + size caps |
| **Medium** | Step 7 | Original | HTML-escape the authorize page |
| **Low** | ADD-4 | New | Use `html.escape` from stdlib instead of custom |
| **Low** | ADD-5 | New | Stop echoing `client_secret` in `/register` |
| **Low** | ADD-6 | New | `redirect_uri` validation |
| **Low** | ADD-7 | New | Stop logging partial session token |
| **Info** | Step 8 | Original | Env hygiene (Railway 2FA, dedicated account) |
| **Info** | ADD-8 | New | Fix `date.today()` → `_local_today()` in two methods |
| **Info** | ADD-9 | New | Add `pip-audit` to CI |
| **Info** | ADD-10 | New | Warn on non-HTTPS `MCP_BASE_URL` |

---

## 5. Updated verification plan

Add these checks to the original §8 verification plan:

9. **Body-size test** — `curl -X POST "$BASE/authorize" --data-binary @/dev/zero --max-time 5` → server returns 413 or drops the connection, does not OOM.
10. **Dict cleanup test** — After deploying, submit 5+ authorize requests with wrong secrets, wait past the `AUTH_WINDOW_S` window, then verify the rate-limit dict is cleaned up (check server memory or add a debug log for dict sizes).
11. **Docker auth test** — Pull the published Docker image, run it with no auth env vars, confirm either (a) it refuses to start, (b) it prints a clear security warning, or (c) it is documented as requiring a reverse proxy.
12. **Timezone regression test** — Call `copy_day` and `get_fasting_history` near midnight Pacific time, confirm they use the correct local date (not UTC).
13. **`/register` response test** — `POST /register` and confirm `client_secret` is not in the response body (if Option A from ADD-5 is implemented; skip if deferred due to connector compatibility).

---

## 6. Files to modify

Summary for the implementing agent:

| File | Changes |
|------|---------|
| `src/cronometer_api_mcp/server.py` | All original Steps 1–7 + ADD-2 (body limit), ADD-3 (dict cleanup), ADD-4 (stdlib html.escape), ADD-5 (/register), ADD-7 (token logging), ADD-10 (HTTPS warning) |
| `src/cronometer_api_mcp/client.py` | ADD-8 (two `date.today()` → `_local_today()` fixes), ADD-7 (session token log) |
| `Dockerfile` | ADD-1 (add comment about auth, or change entrypoint — depending on chosen option) |
| `README.md` | ADD-1 (Docker security warning), original Step 7i docs |
| `.env.example` | Original Step 7i (`MCP_AUTH_TOKEN=`, `MCP_APPROVE_SECRET=`) |
| `pyproject.toml` | ADD-9 (`pip-audit` in dev deps) |
| `.github/workflows/ci.yml` | ADD-9 (audit job) |

---

## 7. What NOT to change

- Tool definitions and annotations in `server.py` — these are correct.
- The MCP tool surface itself — no shell injection, no eval, no unsafe patterns.
- PKCE S256 verification in `_handle_token` — correct, do not regress.
- Single-use code consumption (`pop`) — correct, do not regress.
- `/favicon.ico` special-casing — keep this, it prevents 401 during the authorize page load.
- The `_get_client()` singleton pattern — fine for a single-user server.
- The `_err()` error-wrapping pattern — adequate for MCP tool responses.

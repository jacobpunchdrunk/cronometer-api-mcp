# Security Review & Remediation Plan — cronometer-api-mcp

Status: DRAFT for review. Prepared for implementation, incorporating the lessons and additions adopted during the Basecamp MCP server fix.
Scope: `src/cronometer_api_mcp/server.py` (FastMCP app + `OAuthAuthorizationMiddleware` ASGI wrapper). No tool/client changes proposed.
Upstream: fork of `rwestergren/cronometer-api-mcp`.

---

## 1. TL;DR

This server has the **same critical vulnerability** that was found and fixed in the Basecamp MCP server: the OAuth flow that exists to satisfy Claude's connector is an **unauthenticated token-minting endpoint**. Any anonymous caller who can reach the server can complete the authorize → token exchange and obtain the real `MCP_AUTH_TOKEN`, which then unlocks every MCP tool.

The Basecamp server's own code comments state this OAuth block was "ported from the working Cronometer server (server.py:666)", so this is the original copy of the same flaw.

**Cronometer is a higher-stakes target than Basecamp in one specific way**, and a lower-stakes one in another:
- **Worse:** the server authenticates to Cronometer with your **raw account username and password** (`CRONOMETER_USERNAME` / `CRONOMETER_PASSWORD`), held in env vars and replayed on every session (`client.py`). There is no token on a volume to rotate. If the bearer token is minted by an attacker, they get full read/write to your nutrition/diary/biometric data, and the only way to cut off a leaked *Cronometer credential* is to change your Cronometer password.
- **Better:** the blast radius is your Cronometer data only — not business documents. But the credential-handling means the cleanup story differs from Basecamp (see §3.5).

The fix mirrors Basecamp's, rewritten for this server's ASGI-middleware structure, and includes all the hardening items the second reviewer added during the Basecamp pass (approve-secret gate, code TTL, rate limiting, constant-time compare, min-length guard, proxy-aware client IP).

---

## 2. Method

- Static review of `server.py` and `client.py` via the filesystem.
- Comparison against the now-fixed Basecamp server (`index.ts`) and its two review docs (`SECURITY-REVIEW.md`, `SECURITY-REVIEW-RESPONSE.md`).
- The Basecamp PoC mint chain is structurally identical here; an equivalent incognito `/authorize` check confirms the hole (see §5).

---

## 3. Findings (severity-ranked)

### 3.1 CRITICAL — Unauthenticated OAuth token mint (auth bypass)

In `OAuthAuthorizationMiddleware`, the flow is:

1. `GET /.well-known/oauth-authorization-server` — advertises endpoints. No auth.
2. `POST /register` — returns client credentials to any caller (`_handle_register`). No auth.
3. `GET /authorize` — renders an approve page with a single button to any visitor (`_handle_authorize`). **No authentication of the human.**
4. `POST /authorize` — issues a one-time code; checks only that `redirect_uri` and `code_challenge` are present (`_handle_authorize_submit`).
5. `POST /token` — verifies PKCE, then returns `access_token = self.access_token` (= `MCP_AUTH_TOKEN`) (`_handle_token`).

As with Basecamp, PKCE only proves the same client finished the flow it started; it does **not** authenticate the user. `client_id` / `client_secret` are never validated. Any party who can reach the server can mint the bearer token, then call the MCP endpoint, which is backed by a `CronometerClient` already holding (or able to re-establish from env-var credentials) an authenticated Cronometer session.

The middleware's own docstring describes the authorize step as "just confirming you're the server owner" — but nothing in the code actually confirms that. That is precisely the gap.

Relevant code: `OAuthAuthorizationMiddleware.__call__` and `_handle_authorize` / `_handle_authorize_submit` / `_handle_token`.

### 3.2 HIGH — Server runs unauthenticated if `MCP_AUTH_TOKEN` is unset

In `main()`, for remote transports: if `access_token` (`MCP_AUTH_TOKEN`) is falsy, the middleware is **not applied at all** and the server logs `"No auth configured -- server is unauthenticated"` and serves MCP tools wide open. There is no separate `MCP_AUTH_TOKEN` entry in `.env.example` (only `CRONOMETER_USERNAME` / `CRONOMETER_PASSWORD`), so it is easy to deploy remotely with no gate whatsoever. A misconfiguration should fail closed (refuse to start a remote transport), not fall back to open.

### 3.3 MEDIUM — No auth-code TTL

`_pending_codes` entries persist in memory until consumed or process restart (`_handle_authorize_submit` / `_handle_token`). Codes should expire shortly after issue.

### 3.4 LOW — Non-constant-time token comparison

Bearer validation uses `auth_value != f"Bearer {self.access_token}"` (plain `!=`), which is timing-sensitive. Use a constant-time compare (`hmac.compare_digest`).

### 3.5 INFO / Credential handling (Cronometer-specific)

- Cronometer auth uses **username + password** in env vars, replayed every session (`client.py._get_credentials`). Unlike Basecamp, there is no volume token to delete or rotate. Treat the Railway env vars as live account credentials: confirm Railway 2FA, and if there is any suspicion of exposure, **change the Cronometer account password** (rotating `MCP_AUTH_TOKEN` does not protect the upstream credential).
- Consider whether a dedicated/limited Cronometer account is warranted given the password sits in a third-party platform's env store.

### 3.6 INFO — HTML injection in the authorize page (defense-in-depth)

`_handle_authorize` interpolates `client_id`, `redirect_uri`, `state`, etc. directly into HTML via f-string with no escaping. These come from query params. This is low-impact for a single-user server (you are the only one who should see the page), but the replacement should HTML-escape interpolated values anyway, matching the Basecamp `htmlEscape` approach.

### 3.7 INFO — DNS-rebinding protection disabled

`TransportSecuritySettings(enable_dns_rebinding_protection=False)`. Likely set to work around local/dev host-header checks. Worth revisiting once remote auth is solid; not in scope for this pass, flagged for awareness.

---

## 4. What is already correct (do not regress)

- PKCE S256 verification in `_handle_token` is implemented correctly.
- Auth codes are single-use (`pop`).
- Tool annotations correctly mark read vs. write vs. destructive operations.
- The MCP tool surface itself does not construct shell commands or eval input.
- `/favicon.ico` is special-cased so it doesn't 401 during the authorize page load — keep this.

---

## 5. Proof of concept (pre-fix)

Visual: open in an incognito window (logged out of everything), substituting the live base URL:

```
https://<cronometer-service>.up.railway.app/authorize?response_type=code&redirect_uri=https://example.com/cb&code_challenge=anything&code_challenge_method=S256
```

The approve page renders with no login prompt. This alone confirms §3.1.

Full mint (terminal; equivalent to any anonymous caller). Reuses the PKCE pair from the Basecamp review:

```bash
BASE="https://<cronometer-service>.up.railway.app"
VERIFIER="punchdrunk_pkce_test_verifier_0123456789abcdef"
CHALLENGE="M-8lrNM-WmPXoCaqdohdVHjfLwzUVv6cOPsQ54pEKyo"   # base64url(sha256(VERIFIER))

CODE=$(curl -s -i -X POST "$BASE/authorize" \
  -d "redirect_uri=https://example.com/cb" \
  -d "code_challenge=$CHALLENGE" \
  | grep -i '^location:' | sed -E 's/.*[?&]code=([^&]+).*/\1/' | tr -d '\r')

curl -s -X POST "$BASE/token" \
  -d "grant_type=authorization_code" -d "code=$CODE" -d "code_verifier=$VERIFIER"
```

Pre-fix expected output: `{"access_token":"<MCP_AUTH_TOKEN>","token_type":"bearer","scope":"mcp"}`. **The returned token is live; do not paste it anywhere, and rotate it after testing.**

---

## 6. Remediation plan (ordered)

### Step 0 — Rotate the token now — TODO
Regenerate `MCP_AUTH_TOKEN` with `openssl rand -hex 32`, set in Railway only, never paste into a chat. Note: as with Basecamp, rotation is hygiene, not the fix. **Additionally**, because this server holds your Cronometer password, if you ran the PoC or otherwise suspect exposure, plan to change the Cronometer account password too (§3.5).

### Step 1 — Add `MCP_APPROVE_SECRET` (required for remote) — PROPOSED
A secret the human types once at the `/authorize` page. Separate from `MCP_AUTH_TOKEN` (browser-form exposure vs. header-only). Minimum length 16.

### Step 2 — Gate `/authorize` behind the approval secret — PROPOSED (closes §3.1)
Add a password field to the approve page; validate it (constant-time) on POST before issuing a code.

### Step 3 — Fail closed when no auth is configured — PROPOSED (closes §3.2)
For `sse` / `streamable-http` transports, refuse to start unless both `MCP_AUTH_TOKEN` and `MCP_APPROVE_SECRET` are set. Remove the "unauthenticated fallback"; downgrade it to a hard error. (stdio transport, used locally, needs neither and is unaffected.)

### Step 4 — Auth-code TTL — PROPOSED (closes §3.3)
Store `created_at`; reject codes older than 5 minutes at `/token`.

### Step 5 — Constant-time comparisons — PROPOSED (closes §3.4)
`hmac.compare_digest` for the bearer check and the new approve-secret check.

### Step 6 — Per-IP rate limiting on `/authorize` failures — PROPOSED
5 failed attempts/minute/IP → 429. **Proxy-aware:** behind Railway's edge, the real client IP is in `X-Forwarded-For`, not the socket peer. (This is the lesson from the Basecamp build — `app.set("trust proxy", 1)` there.) In this ASGI server there is no Express `trust proxy`; derive the client IP by taking the **last** entry of `X-Forwarded-For` (the value appended by Railway's trusted edge), NOT the left-most (client-controlled, spoofable). If `X-Forwarded-For` is absent, fall back to the ASGI `client` peer. Document the one-hop assumption.

### Step 7 — HTML-escape the authorize page — PROPOSED (closes §3.6)
Escape all interpolated query-param values.

### Step 8 — Env hygiene — PROPOSED (addresses §3.5)
Confirm Railway 2FA. Consider a dedicated Cronometer account. There are no volume-seed vars to delete here (unlike Basecamp).

---

## 7. Proposed code changes (for reviewer to evaluate)

All in `server.py`. Because this is ASGI middleware rather than Express, the structure differs from Basecamp but the logic is the same.

### 7a. Module-level helpers (top of file, near imports)

```python
import hmac
import time
from hashlib import sha256


def _safe_equal(a: str, b: str) -> bool:
    """Constant-time string comparison (length-independent)."""
    return hmac.compare_digest(sha256(a.encode()).digest(), sha256(b.encode()).digest())


def _html_escape(s: str | None) -> str:
    s = s or ""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
```

### 7b. Middleware constructor — accept the approve secret + add stores

```python
def __init__(
    self,
    app,
    *,
    client_id: str,
    client_secret: str,
    access_token: str,
    approve_secret: str,            # NEW
    base_url: str = "",
):
    self.app = app
    self.client_id = client_id
    self.client_secret = client_secret
    self.access_token = access_token
    self.approve_secret = approve_secret          # NEW
    self.base_url = base_url.rstrip("/")
    self._pending_codes: dict[str, dict] = {}
    # NEW: per-IP failed-attempt tracking for /authorize
    self._auth_attempts: dict[str, dict] = {}     # ip -> {count, reset_at}

CODE_TTL_S = 5 * 60
MAX_AUTH_ATTEMPTS = 5
AUTH_WINDOW_S = 60
```

(Define the three constants at module scope or as class attributes — reviewer's preference.)

### 7c. Bearer check — constant-time (in `__call__`)

```python
auth_value = headers.get(b"authorization", b"").decode()
expected = f"Bearer {self.access_token}"
if not _safe_equal(auth_value, expected):
    # ... existing 401 response ...
```

### 7d. Client-IP helper (proxy-aware)

```python
def _client_ip(self, scope, headers) -> str:
    xff = headers.get(b"x-forwarded-for", b"").decode()
    if xff:
        # Railway's edge appends the real client IP as the LAST entry.
        # The left-most entries are client-supplied and spoofable, so do
        # NOT trust them. One-hop assumption (Railway edge in front).
        return xff.split(",")[-1].strip()
    client = scope.get("client")
    return client[0] if client else "unknown"
```

### 7e. Authorize page renderer — password field + escaping

```python
def _render_approve_page(self, *, client_id, redirect_uri, code_challenge,
                         code_challenge_method, state, error: str = "") -> str:
    e = _html_escape
    err_html = f'<p class="err">{e(error)}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html><head><title>Authorize MCP Access</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 20px; }}
  h1 {{ font-size: 1.4em; }}
  .info {{ background: #f0f4f8; padding: 16px; border-radius: 8px; margin: 20px 0; }}
  .err {{ color: #b91c1c; font-weight: 600; margin: 8px 0; }}
  label {{ display:block; margin: 16px 0 6px; font-weight: 600; }}
  input[type=password] {{ width: 100%; padding: 10px; font-size: 16px; box-sizing: border-box;
                          border: 1px solid #cbd5e1; border-radius: 6px; }}
  button {{ background: #2563eb; color: white; border: none; padding: 12px 32px;
           border-radius: 6px; font-size: 16px; cursor: pointer; margin-top: 16px; }}
</style></head>
<body>
  <h1>Authorize Cronometer MCP</h1>
  <div class="info">
    <p><strong>Client:</strong> {e(client_id) or "unknown"}</p>
    <p>Enter the access secret to grant this client access to your Cronometer data.</p>
  </div>
  {err_html}
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id" value="{e(client_id)}">
    <input type="hidden" name="redirect_uri" value="{e(redirect_uri)}">
    <input type="hidden" name="code_challenge" value="{e(code_challenge)}">
    <input type="hidden" name="code_challenge_method" value="{e(code_challenge_method)}">
    <input type="hidden" name="state" value="{e(state)}">
    <label for="approve_secret">Access secret</label>
    <input id="approve_secret" type="password" name="approve_secret" autocomplete="off" autofocus required>
    <button type="submit">Authorize</button>
  </form>
</body></html>"""
```

`_handle_authorize` (GET) renders this with `error=""`.

### 7f. `_handle_authorize_submit` (POST) — throttle + validate secret before issuing a code

```python
# ... parse redirect_uri, code_challenge, code_challenge_method, state, approve_secret ...

ip = self._client_ip(scope, dict(scope.get("headers", [])))
now = time.monotonic()

# throttle check
entry = self._auth_attempts.get(ip)
if entry and now < entry["reset_at"] and entry["count"] >= MAX_AUTH_ATTEMPTS:
    html = self._render_approve_page(..., error="Too many attempts. Wait a minute.")
    await HTMLResponse(html, status_code=429)(scope, receive, send)
    return

# secret check (constant-time)
if not approve_secret or not _safe_equal(approve_secret, self.approve_secret):
    e = self._auth_attempts.get(ip)
    if not e or now > e["reset_at"]:
        self._auth_attempts[ip] = {"count": 1, "reset_at": now + AUTH_WINDOW_S}
    else:
        e["count"] += 1
    html = self._render_approve_page(..., error="Incorrect secret. Try again.")
    await HTMLResponse(html, status_code=403)(scope, receive, send)
    return

# success → clear attempts, issue code with TTL
self._auth_attempts.pop(ip, None)
code = secrets.token_urlsafe(32)
self._pending_codes[code] = {
    "code_challenge": code_challenge,
    "code_challenge_method": code_challenge_method or "S256",
    "redirect_uri": redirect_uri,
    "created_at": time.monotonic(),   # NEW
}
# ... existing redirect ...
```

### 7g. `_handle_token` — enforce TTL after consuming the code

```python
pending = self._pending_codes.pop(code, None)
if pending is None:
    # ... existing invalid_grant ...
    return

if time.monotonic() - pending.get("created_at", 0) > CODE_TTL_S:
    await JSONResponse({"error": "invalid_grant",
                        "error_description": "Code expired"}, status_code=400)(scope, receive, send)
    return
# ... existing PKCE check ...
```

### 7h. `main()` — require secrets for remote transports; fail closed

```python
elif transport in ("sse", "streamable-http"):
    import uvicorn
    # ...
    access_token = os.getenv("MCP_AUTH_TOKEN")
    approve_secret = os.getenv("MCP_APPROVE_SECRET")
    client_id = os.getenv("MCP_OAUTH_CLIENT_ID", "")
    client_secret = os.getenv("MCP_OAUTH_CLIENT_SECRET", "")
    base_url = os.getenv("MCP_BASE_URL", f"http://localhost:{port}")

    if not access_token or not approve_secret:
        raise RuntimeError(
            "Remote transport requires MCP_AUTH_TOKEN and MCP_APPROVE_SECRET. "
            "Refusing to start unauthenticated."
        )
    if len(approve_secret) < 16:
        raise RuntimeError("MCP_APPROVE_SECRET too short (min 16). Use: openssl rand -hex 32")

    app = OAuthAuthorizationMiddleware(
        app,
        client_id=client_id,
        client_secret=client_secret,
        access_token=access_token,
        approve_secret=approve_secret,
        base_url=base_url,
    )
    # ... uvicorn run ...
```

The previous `if access_token: ... else: warn "unauthenticated"` branch is removed — remote now fails closed.

### 7i. Docs

- `.env.example`: add `MCP_AUTH_TOKEN=`, `MCP_APPROVE_SECRET=`, and note that remote transports require both (with the `openssl rand -hex 32` hint and "keep them distinct"). Keep the Cronometer credential lines.
- `README.md`: in the remote/hosted section, document the browser approve step prompting for `MCP_APPROVE_SECRET`, and that the server now refuses to start a remote transport without both secrets.

---

## 8. Verification plan (post-fix)

1. Lint/type as the repo is set up (e.g. `uv run ruff check` / `uv run pytest` if present).
2. Set `MCP_AUTH_TOKEN` and `MCP_APPROVE_SECRET` in Railway; deploy.
3. **Negative test** — re-run the §5 mint chain. Expected: `POST /authorize` returns 403 (no code), `/token` returns `invalid_grant`. No token obtainable.
4. **Fail-closed test** — temporarily unset `MCP_APPROVE_SECRET` in a throwaway deploy/local run → server refuses to start the remote transport (don't ship this; just confirm the guard).
5. **Rate-limit test** — 6 wrong secrets in <1 min → 6th returns 429. Confirm the count is keyed to your real IP (i.e. it actually triggers), validating the `X-Forwarded-For` last-entry logic. Run this LAST (it throttles your IP for a minute, which would block the browser approve step).
6. **Bearer gate** — MCP request with no `Authorization` → 401; with correct Bearer → not 401.
7. **Legit flow** — add/reconnect the connector in Claude → approve page shows the password field → enter `MCP_APPROVE_SECRET` → flow completes → tools register → ask Claude to read a day's food log.
8. **Token rotation** — rotate `MCP_AUTH_TOKEN` again if exposed during testing; change the Cronometer password if there's any suspicion the upstream credential leaked.

---

## 9. Cross-server status

- **Basecamp MCP server:** FIXED and verified in production (gated approve step, header-only auth, constant-time compare, code TTL, rate limiting, proxy-aware IP). This plan ports the same protections here.
- **Future Google Workspace server:** must NOT reuse this single-user static-token shim. A server with read/write to all business documents/email requires per-user OAuth via a real identity provider (Google sign-in), with access scoped per user. The shared-secret approve gate is an acceptable stopgap only for these personal, single-user servers (Basecamp, Cronometer).

---

## 10. Decisions for the reviewing agent

1. Confirm `MCP_APPROVE_SECRET` separate from `MCP_AUTH_TOKEN` (recommended), consistent with the Basecamp fix.
2. Confirm fail-closed for remote transports (§3.2 / Step 3) — i.e. removing the unauthenticated fallback entirely. (Recommended; the fallback is a foot-gun.)
3. Confirm the `X-Forwarded-For` **last-entry** parsing is correct for Railway's edge topology (one-hop assumption). If Railway's forwarding differs, adjust the index.
4. Confirm scope limited to `server.py` + env/docs, with `client.py` and the tool definitions untouched.
5. Decide whether to also address §3.7 (DNS-rebinding protection) now or defer.

# Backlog — non-blocking follow-ups

These are cleanup / nice-to-have items left after the OAuth security hardening
(see SECURITY-REVIEW.md and SECURITY-REVIEW-RESPONSE.md). **None of these are
security holes or blockers.** The critical fix (anonymous token-mint via the
OAuth flow) is closed and verified in production. These can be done whenever.

---

## 1. Run the formatter so CI lint passes (cosmetic)

The hand-written OAuth/hardening changes may not match `ruff`'s exact
formatting, so the CI lint job (`ruff check` / `ruff format --check`) may be
red. A red lint badge does NOT mean anything is broken — it's whitespace/style
only. The security fix works regardless (verified via smoke tests).

To fix and get green CI:

```bash
# If uv/ruff are on PATH:
uv run ruff format
uv run ruff check --fix

# If "command not found" (uv/ruff not on PATH), use pip instead:
python3 -m pip install --user ruff
python3 -m ruff format
python3 -m ruff check --fix
```

Then commit the formatting-only changes and push. (Note: `~/.local/bin` may
need to be on PATH for a user-installed `ruff` to be found, or invoke via
`python3 -m ruff` as above.)

---

## 2. Fresh reviewer on the final committed diffs (optional, belt-and-suspenders)

Earlier review covered the *plan* (SECURITY-REVIEW-RESPONSE.md, written before
the code). This item is to review the *actual committed code* after the fact.

Rationale: two real bugs were introduced and caught during implementation
(a deleted `grant_type` assignment in `/token`, and a `TypeError` on `None`
in the approve-page renderer that 500'd every failed-secret submission). Both
fixed and verified. A second read of the finished diff is cheap insurance
against a third bug that neither testing nor the author noticed — tests only
cover the paths you test; a code read covers the ones you didn't.

How to do it: point a fresh agent (or a person) at the committed diff for the
security commit(s) — `git diff <base>..HEAD` on `server.py`, `client.py`, and
the docs — and ask for a security-correctness review, same framing as the plan
review. Focus areas worth calling out:
- `_handle_authorize_submit`: throttle + constant-time secret check + code TTL
- `_handle_token`: PKCE + TTL enforcement
- `_render_approve_page`: None-handling and HTML escaping
- `main()`: fail-closed guard for remote transports
- `_cleanup_expired`: list-before-evict (no dict-mutation-during-iteration)

---

## 3. Minor / informational (from SECURITY-REVIEW-RESPONSE.md, deferred)

- **Rate-limit off-by-one (cosmetic):** threshold is `count >= MAX_AUTH_ATTEMPTS`,
  so the limiter trips on the 5th failed attempt rather than the 6th. Intended
  ceiling (~5 guesses/min) is preserved; not worth a redeploy on its own.
- **`redirect_uri` validation (ADD-6, deferred):** not validated against a
  registered/allowlisted value. PKCE + the approve-secret gate make this low
  risk. Implement if convenient (e.g. allowlist Claude connector callback
  patterns).
- **DNS-rebinding protection (ADD-7 / §3.7, deferred):**
  `TransportSecuritySettings(enable_dns_rebinding_protection=False)`. Revisit
  re-enabling now that the auth gate is solid; verify it doesn't break the
  host-header handling first.
- **`pip-audit` in CI (ADD-9, done):** added to `ci.yml` + dev deps. If it ever
  flags an advisory in `httpx`/`uvicorn`/`mcp`/etc., triage then.

---

## 4. Operational hygiene (not code)

- Confirm **2FA is enabled on the Railway account** — it holds live Cronometer
  credentials (`CRONOMETER_USERNAME` / `CRONOMETER_PASSWORD`) as env vars.
- Consider a **dedicated/limited Cronometer account** for the server rather than
  the primary account, since the password lives in a third-party platform's env
  store.
- Decide what to do with `SECURITY-REVIEW.md` / `SECURITY-REVIEW-RESPONSE.md`
  (keep as a record, move to a `docs/` folder, or delete).

---

## Note for the future Google Workspace MCP (the original goal)

Do NOT reuse this single-user, static-token + shared-approve-secret pattern for
a server with read/write access to all business documents and email. That needs
**per-user OAuth via a real identity provider (Google sign-in)** so access is
scoped per user with no shared secret or god-token in the middle. The pattern in
this repo was an acceptable fix for a personal, single-user server only.

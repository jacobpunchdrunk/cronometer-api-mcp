# Deploying (Cloudflare)

> Ours, not upstream. Replaces the Railway deployment, retired after Railway's
> October 2026 environment-variable breach. No secrets live here.

## What runs where

- **Worker** `cronometer-mcp` (code in `worker/`). A thin forwarder: it refuses to serve until
  secrets are set, overwrites `X-Forwarded-For` with Cloudflare's verified client IP (the
  server rate-limits approve-secret attempts by that header), and passes every request through.
- **Container** (`deploy/cf.Dockerfile`). The unchanged Python server on the native
  `streamable-http` transport, so its built-in OAuth approve-secret gate is always on. Only the
  Worker can reach it. The repo-root `Dockerfile` (supergateway, stdio, no auth) is not used.
- **Connector URL:** `https://cronometer-mcp.punchdrunk.workers.dev/mcp`
- **Sleep:** one `basic` instance, sleeps after 1 hour idle. Cold start is a few seconds; the
  connector simply waits.
- **Cost:** covered by the existing Workers Paid plan ($5/month) plus container usage while awake.

## Deploy

Docker must be running (the image builds locally): `colima start`.

```sh
cd worker
npm ci
npx wrangler deploy
```

## Secrets

Doppler project `cronometer-api-mcp`, config `prd` (deployed) and `dev` (local).

| Name                  | What it is                                                       |
| --------------------- | ---------------------------------------------------------------- |
| `CRONOMETER_USERNAME` | Cronometer account email                                         |
| `CRONOMETER_PASSWORD` | Cronometer password                                              |
| `MCP_AUTH_TOKEN`      | Bearer token the server issues to claude.ai. `openssl rand -hex 32` |
| `MCP_APPROVE_SECRET`  | Typed once on the approve page when connecting. Distinct from the token, min 16 chars |

Doppler has no native sync to Workers, so copy with one command (prints names only). Re-run it
after any change in Doppler `prd`:

```sh
doppler secrets download --project cronometer-api-mcp --config prd --no-file --format json \
  | jq -c '{CRONOMETER_USERNAME, CRONOMETER_PASSWORD, MCP_AUTH_TOKEN, MCP_APPROVE_SECRET}' \
  | (cd worker && npx wrangler secret bulk)
```

The container reads secrets when it starts. After changing one, make it restart: redeploy, or
wait for it to sleep.

Rotating `MCP_AUTH_TOKEN` logs claude.ai out; reconnect the connector and enter the approve secret.

## Logs

`npx wrangler tail` in `worker/`. Container logs: Cloudflare dashboard, Workers & Pages,
`cronometer-mcp`, Containers.

## Local

```sh
docker build --platform linux/amd64 -f deploy/cf.Dockerfile -t cronometer-cf .
```

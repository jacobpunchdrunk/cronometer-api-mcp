// worker/src/index.ts
//
// Cloudflare Worker in front of the Cronometer MCP container.
//
//   claude.ai ──► Worker ──► Container (unchanged Python server, native
//                            streamable-http + its own OAuth approve-secret gate)
//
// The Worker is a thin forwarder: it checks secrets are configured, sets the
// real client IP for the server's rate limiter, and passes everything else
// through. Auth stays in the Python server so the connector flow is the same
// one that ran on Railway. See DEPLOY.md.

import { Container, getContainer } from '@cloudflare/containers';

export interface Env {
  MCP_CONTAINER: DurableObjectNamespace<CronometerContainer>;
  MCP_BASE_URL: string;
  CRONOMETER_TIMEZONE: string;
  CRONOMETER_USERNAME?: string;
  CRONOMETER_PASSWORD?: string;
  MCP_AUTH_TOKEN?: string;
  MCP_APPROVE_SECRET?: string;
}

const REQUIRED = [
  'CRONOMETER_USERNAME',
  'CRONOMETER_PASSWORD',
  'MCP_AUTH_TOKEN',
  'MCP_APPROVE_SECRET',
] as const;

export function missingSecrets(env: Env): string[] {
  return REQUIRED.filter((k) => !env[k]);
}

/** One instance: auth codes and Cronometer sessions live in its memory. */
const INSTANCE_NAME = 'singleton';

export class CronometerContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = '1h';

  constructor(ctx: DurableObjectState<{}>, env: Env) {
    super(ctx, env);
    this.envVars = {
      MCP_TRANSPORT: 'streamable-http',
      PORT: '8080',
      MCP_BASE_URL: env.MCP_BASE_URL,
      CRONOMETER_TIMEZONE: env.CRONOMETER_TIMEZONE,
      CRONOMETER_USERNAME: env.CRONOMETER_USERNAME ?? '',
      CRONOMETER_PASSWORD: env.CRONOMETER_PASSWORD ?? '',
      MCP_AUTH_TOKEN: env.MCP_AUTH_TOKEN ?? '',
      MCP_APPROVE_SECRET: env.MCP_APPROVE_SECRET ?? '',
    };
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const missing = missingSecrets(env);
    if (missing.length > 0) {
      // Names only, never values.
      return new Response(`Not configured: missing secrets ${missing.join(', ')}`, {
        status: 503,
      });
    }
    // The server rate-limits approve-secret attempts by the LAST X-Forwarded-For
    // entry. Overwrite it with Cloudflare's verified client IP so it can't be spoofed.
    const headers = new Headers(request.headers);
    headers.set('x-forwarded-for', request.headers.get('cf-connecting-ip') ?? 'unknown');
    return getContainer(env.MCP_CONTAINER, INSTANCE_NAME).fetch(new Request(request, { headers }));
  },
} satisfies ExportedHandler<Env>;

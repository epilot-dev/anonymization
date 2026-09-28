import { createAnonymizer } from '@epilot/anonymization';
import {
  FULLSTORY_BLOCKED_TOOLS,
  FULLSTORY_KEEP_URL_HOSTS,
  FULLSTORY_OVERRIDES,
  FULLSTORY_USER_PROPERTY_KEYS,
  fullstoryUpstreamFromApiKey,
} from './fullstory';
import { createSanitizer, type Sanitizer } from './sanitize';

export type ProxyConfig = {
  port: number;
  /** path the MCP endpoint is served on; `<path>/<token>` also accepted (for clients without custom headers) */
  path: string;
  upstreamUrl: string;
  upstreamApiKey: string;
  /** client credentials accepted by the proxy (one per user/client, so they can be revoked individually) */
  proxyTokens: string[];
  isToolBlocked: (name: string) => boolean;
  sanitizer: Sanitizer;
  maxBodyBytes: number;
  log: (entry: Record<string, unknown>) => void;
};

const list = (value: string | undefined): string[] | undefined =>
  value === undefined
    ? undefined
    : value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);

export const loadConfig = (env: NodeJS.ProcessEnv = process.env): ProxyConfig => {
  const upstreamApiKey = env.UPSTREAM_API_KEY ?? env.FULLSTORY_API_KEY;
  if (!upstreamApiKey) {
    throw new Error('FULLSTORY_API_KEY (or UPSTREAM_API_KEY) is required');
  }

  const proxyTokens = list(env.PROXY_TOKENS) ?? [];
  if (proxyTokens.length === 0 && env.ALLOW_UNAUTHENTICATED !== 'true') {
    // the proxy holds an org-wide API key: never expose it unauthenticated by accident
    throw new Error('PROXY_TOKENS is required (set ALLOW_UNAUTHENTICATED=true for local dev only)');
  }

  const log = (entry: Record<string, unknown>) => console.log(JSON.stringify({ ts: new Date().toISOString(), ...entry }));

  if (!env.ANONYMIZATION_SECRET) {
    log({ level: 'warn', msg: 'ANONYMIZATION_SECRET not set: PII is statically redacted instead of pseudonymized' });
  }

  const blocked = new Set(list(env.BLOCKED_TOOLS) ?? FULLSTORY_BLOCKED_TOOLS);
  const allowed = list(env.ALLOWED_TOOLS);
  const allowedSet = allowed && new Set(allowed);
  const isToolBlocked = (name: string) => blocked.has(name) || (allowedSet !== undefined && !allowedSet.has(name));

  const anonymizer = createAnonymizer({
    orgId: env.ANONYMIZATION_ORG_ID ?? 'fullstory',
    secret: env.ANONYMIZATION_SECRET,
    overrides: FULLSTORY_OVERRIDES,
  });

  const sanitizer = createSanitizer({
    anonymizer,
    userPropertyKeys: env.USER_PROPERTY_KEYS ? new RegExp(env.USER_PROPERTY_KEYS, 'i') : FULLSTORY_USER_PROPERTY_KEYS,
    keepUserProperties: list(env.KEEP_USER_PROPERTIES),
    keepUrlHosts: FULLSTORY_KEEP_URL_HOSTS,
    allowBinaryContent: env.ALLOW_BINARY_CONTENT === 'true',
    isToolBlocked,
  });

  return {
    port: Number(env.PORT ?? 8080),
    path: env.MCP_PATH ?? '/mcp',
    upstreamUrl: env.UPSTREAM_URL ?? fullstoryUpstreamFromApiKey(upstreamApiKey),
    upstreamApiKey,
    proxyTokens,
    isToolBlocked,
    sanitizer,
    maxBodyBytes: Number(env.MAX_BODY_BYTES ?? 1_000_000),
    log,
  };
};

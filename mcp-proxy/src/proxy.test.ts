import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from './config';
import { createProxyServer } from './server';

const env = {
  FULLSTORY_API_KEY: 'eu1.test-key',
  PROXY_TOKENS: 'tok-a,tok-b',
  ANONYMIZATION_SECRET: 'test-secret',
  KEEP_USER_PROPERTIES: 'plan',
};
const silent = () => undefined;

const sessionEvents = {
  session: {
    url: 'https://app.eu1.fullstory.com/ui/o-123/session/1234:5678',
    user_properties: {
      displayName: 'Max Mustermann',
      email: 'max@web.de',
      uid: 'user-42',
      plan: 'enterprise',
      favorite_customer: 'Erika Musterfrau',
    },
  },
  events: [
    { type: 'navigate', page_url: 'https://portal.epilot.cloud/app/contacts?search=Erika%20Musterfrau&id=9' },
    { type: 'error', message: 'Could not send mail to erika@example.org' },
    { type: 'click', target: 'Save button', count: 3 },
  ],
};

describe('sanitizer', () => {
  const { sanitizer } = { ...loadConfig(env), log: silent };

  it('strictly anonymizes user property bags, keeps allow-listed keys and structure', () => {
    const out = sanitizer.sanitizeJson(sessionEvents) as typeof sessionEvents;
    const props = out.session.user_properties;

    expect(props.displayName).toMatch(/^person_[0-9a-f]+$/);
    expect(props.email).toMatch(/@anonymized\.invalid$/);
    expect(props.uid).toMatch(/^value_[0-9a-f]+$/);
    expect(props.plan).toBe('enterprise');
    expect(props.favorite_customer).toBe('[REDACTED]');
    // deterministic -> joinable across tool calls
    expect((sanitizer.sanitizeJson(sessionEvents) as typeof sessionEvents).session.user_properties.uid).toBe(props.uid);
  });

  it('redacts URL query strings except on Fullstory hosts, scrubs embedded identifiers', () => {
    const out = JSON.stringify(sanitizer.sanitizeJson(sessionEvents));

    expect(out).toContain('https://app.eu1.fullstory.com/ui/o-123/session/1234:5678');
    expect(out).toContain('contacts?search=REDACTED&id=REDACTED');
    expect(out).not.toMatch(/Musterfrau|Mustermann|max@web\.de|erika@example\.org|user-42/);
    expect(out).toContain('Save button');
  });

  it('handles markdown/prose tool output', () => {
    const text = [
      '## Session 1234:5678',
      '- **Display Name:** Max Mustermann',
      '- **Email:** erika@example.org',
      '- Email: max@web.de',
      '- Plan: enterprise',
      'Visited https://portal.epilot.cloud/app?email=max%40web.de',
    ].join('\n');
    const out = sanitizer.sanitizeText(text);

    expect(out).not.toMatch(/Mustermann|max@web\.de|max%40web/);
    expect(out).toContain('- Plan: enterprise');
    expect(out).toContain('## Session 1234:5678');
  });

  it('replaces binary content and hides blocked tools', () => {
    const shot = sanitizer.sanitizePayload({
      jsonrpc: '2.0',
      id: 1,
      result: { content: [{ type: 'image', data: 'iVBOR…', mimeType: 'image/png' }] },
    }) as { result: { content: { type: string }[] } };
    expect(shot.result.content[0].type).toBe('text');

    const list = sanitizer.sanitizePayload({
      jsonrpc: '2.0',
      id: 2,
      result: { tools: [{ name: 'session_screenshot' }, { name: 'compute_metric' }] },
    }) as { result: { tools: { name: string }[] } };
    expect(list.result.tools.map((t) => t.name)).toEqual(['compute_metric']);
  });
});

describe('proxy server (fake upstream)', () => {
  let upstream: http.Server;
  let proxy: http.Server;
  let proxyUrl: string;
  const seen: { authorization?: string; cookie?: string }[] = [];

  beforeAll(async () => {
    upstream = http.createServer((req, res) => {
      seen.push({ authorization: req.headers.authorization, cookie: req.headers.cookie });
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const msg = JSON.parse(body);
        const result = { content: [{ type: 'text', text: JSON.stringify(sessionEvents) }] };
        if (msg.params?.name === 'get_session_events_sse') {
          res.writeHead(200, { 'content-type': 'text/event-stream', 'mcp-session-id': 's-1' });
          res.write(`id: 1\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { data: 'hi max@web.de' } })}\n\n`);
          res.end(`id: 2\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: msg.id, result })}\n\n`);
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': 's-1' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result }));
      });
    });
    await new Promise<void>((r) => upstream.listen(0, r));
    const upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/mcp/fullstory`;

    proxy = createProxyServer({ ...loadConfig({ ...env, UPSTREAM_URL: upstreamUrl }), log: silent });
    await new Promise<void>((r) => proxy.listen(0, r));
    proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}/mcp`;
  });

  afterAll(() => {
    proxy.close();
    upstream.close();
  });

  const call = (name: string, auth: Record<string, string> = { authorization: 'Bearer tok-a' }, url = proxyUrl) =>
    fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', cookie: 'x=1', ...auth },
      body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name, arguments: {} } }),
    });

  it('rejects missing / wrong client tokens', async () => {
    expect((await call('get_session_events', {})).status).toBe(401);
    expect((await call('get_session_events', { authorization: 'Bearer nope' })).status).toBe(401);
  });

  it('accepts path tokens, swaps credentials, drops client headers, anonymizes JSON responses', async () => {
    const res = await call('get_session_events', {}, `${proxyUrl}/tok-b`);
    expect(res.status).toBe(200);
    expect(res.headers.get('mcp-session-id')).toBe('s-1');
    const text = JSON.stringify(await res.json());

    expect(text).not.toMatch(/Mustermann|max@web\.de|user-42/);
    expect(seen.at(-1)).toEqual({ authorization: 'Bearer eu1.test-key', cookie: undefined });
  });

  it('anonymizes SSE streams event by event', async () => {
    const res = await call('get_session_events_sse');
    const text = await res.text();

    expect(res.headers.get('content-type')).toContain('text/event-stream');
    expect(text).toMatch(/^id: 1\ndata: /);
    expect(text).toContain('id: 2');
    expect(text).not.toMatch(/Mustermann|max@web\.de|user-42/);
  });

  it('answers blocked tools locally without calling upstream', async () => {
    const before = seen.length;
    const res = await call('session_screenshot');
    const body = (await res.json()) as { result: { isError: boolean } };

    expect(body.result.isError).toBe(true);
    expect(seen.length).toBe(before);
  });
});

describe('markdown key/value lines', () => {
  const { sanitizer } = loadConfig(env);

  it('keeps bold markers and pseudonymizes the value only', () => {
    expect(sanitizer.sanitizeText('- **Display Name:** Max Mustermann')).toMatch(/^- \*\*Display Name:\*\* person_[0-9a-f]+$/);
  });
});

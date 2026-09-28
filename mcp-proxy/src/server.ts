import { createHash, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import { Readable } from 'node:stream';
import type { ProxyConfig } from './config';
import type { JsonRpcMessage } from './sanitize';
import { transformSse } from './sse';

/** request headers forwarded upstream; everything else (cookies, client auth, …) is dropped */
const FORWARD_REQUEST_HEADERS = ['content-type', 'accept', 'mcp-session-id', 'mcp-protocol-version', 'last-event-id'];
/** response headers forwarded to the client; `www-authenticate` is dropped so clients don't try OAuth against us */
const FORWARD_RESPONSE_HEADERS = ['content-type', 'mcp-session-id', 'mcp-protocol-version', 'cache-control'];

const digest = (value: string) => createHash('sha256').update(value).digest();

const sendJson = (res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};

const readBody = async (req: http.IncomingMessage, limit: number): Promise<string> => {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) {
      throw Object.assign(new Error('payload too large'), { status: 413 });
    }
    chunks.push(chunk as Buffer);
  }

  return Buffer.concat(chunks).toString('utf8');
};

const blockedToolResult = (message: JsonRpcMessage, name: string): JsonRpcMessage => ({
  jsonrpc: '2.0',
  id: message.id ?? null,
  result: {
    content: [
      {
        type: 'text',
        text: `Tool "${name}" is disabled by the epilot anonymizing proxy: its output cannot be anonymized reliably.`,
      },
    ],
    isError: true,
  },
});

export const createProxyServer = (config: ProxyConfig): http.Server => {
  const tokenDigests = config.proxyTokens.map(digest);

  const isAuthorized = (req: http.IncomingMessage, pathToken: string | undefined): boolean => {
    if (tokenDigests.length === 0) {
      return true; // ALLOW_UNAUTHENTICATED
    }
    const header = req.headers.authorization;
    const presented = header?.startsWith('Bearer ') ? header.slice(7) : pathToken;
    if (!presented) {
      return false;
    }
    const presentedDigest = digest(presented);

    return tokenDigests.some((expected) => timingSafeEqual(expected, presentedDigest));
  };

  return http.createServer(async (req, res) => {
    const started = Date.now();
    const url = new URL(req.url ?? '/', 'http://localhost');
    const logEntry: Record<string, unknown> = { method: req.method, path: config.path };

    try {
      if (url.pathname === '/healthz') {
        return sendJson(res, 200, { ok: true });
      }

      const isMcpPath = url.pathname === config.path || url.pathname.startsWith(`${config.path}/`);
      if (!isMcpPath) {
        return sendJson(res, 404, { error: 'not found' });
      }
      const pathToken = url.pathname.length > config.path.length ? url.pathname.slice(config.path.length + 1) : undefined;
      if (!isAuthorized(req, pathToken)) {
        return sendJson(res, 401, { error: 'unauthorized' });
      }
      if (!['POST', 'GET', 'DELETE'].includes(req.method ?? '')) {
        return sendJson(res, 405, { error: 'method not allowed' }, { allow: 'GET, POST, DELETE' });
      }

      let body: string | undefined;
      if (req.method === 'POST') {
        body = await readBody(req, config.maxBodyBytes);
        let parsed: JsonRpcMessage | JsonRpcMessage[];
        try {
          parsed = JSON.parse(body);
        } catch {
          return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
        }
        const messages = Array.isArray(parsed) ? parsed : [parsed];
        logEntry.rpc = messages.map((m) => (m.method === 'tools/call' ? `tools/call:${m.params?.name}` : m.method));

        const blocked = messages.filter(
          (m) => m.method === 'tools/call' && typeof m.params?.name === 'string' && config.isToolBlocked(m.params.name),
        );
        if (blocked.length > 0) {
          // answer locally, never forward; batches containing a blocked call are rejected as a whole
          const responses = messages
            .filter((m) => m.id !== undefined)
            .map((m) =>
              blocked.includes(m)
                ? blockedToolResult(m, String(m.params?.name))
                : { jsonrpc: '2.0', id: m.id, error: { code: -32600, message: 'Batch rejected: contains a disabled tool' } },
            );
          logEntry.status = 200;
          logEntry.blocked = blocked.map((m) => m.params?.name);

          return sendJson(res, 200, Array.isArray(parsed) ? responses : responses[0]);
        }
      }

      const headers: Record<string, string> = { authorization: `Bearer ${config.upstreamApiKey}` };
      for (const name of FORWARD_REQUEST_HEADERS) {
        const value = req.headers[name];
        if (typeof value === 'string') {
          headers[name] = value;
        }
      }

      const upstream = await fetch(config.upstreamUrl, { method: req.method, headers, body });
      logEntry.status = upstream.status;

      const responseHeaders: Record<string, string> = {};
      for (const name of FORWARD_RESPONSE_HEADERS) {
        const value = upstream.headers.get(name);
        if (value) {
          responseHeaders[name] = value;
        }
      }

      if (upstream.status === 401 || upstream.status === 403) {
        // upstream rejected OUR key: don't make the client think it must re-authenticate
        return sendJson(res, 502, { error: 'upstream rejected the proxy credentials' });
      }

      const contentType = upstream.headers.get('content-type') ?? '';

      if (contentType.includes('text/event-stream') && upstream.body) {
        res.writeHead(upstream.status, responseHeaders);
        const events = transformSse(
          Readable.fromWeb(upstream.body as import('node:stream/web').ReadableStream<Uint8Array>),
          config.sanitizer.sanitizeMessage,
        );
        req.on('close', () => void events.return(undefined));
        for await (const event of events) {
          res.write(event);
        }

        return res.end();
      }

      const text = await upstream.text();

      if (contentType.includes('application/json')) {
        let payload: unknown;
        try {
          payload = JSON.parse(text);
        } catch {
          return sendJson(res, 502, { error: 'upstream returned invalid JSON' });
        }

        return sendJson(res, upstream.status, config.sanitizer.sanitizePayload(payload), responseHeaders);
      }

      if (text.length === 0) {
        res.writeHead(upstream.status, responseHeaders);

        return res.end();
      }

      // unexpected body type: fail safe, never pass through unsanitized
      return sendJson(res, 502, { error: `unsupported upstream content-type: ${contentType || 'none'}` });
    } catch (error) {
      const status = (error as { status?: number }).status ?? 502;
      logEntry.status = status;
      logEntry.error = (error as Error).message;
      if (!res.headersSent) {
        sendJson(res, status, { error: status === 413 ? 'payload too large' : 'upstream error' });
      } else {
        res.end();
      }
    } finally {
      // never log bodies: they are exactly the data this proxy exists to keep out of places
      config.log({ ...logEntry, ms: Date.now() - started });
    }
  });
};

import type { JsonRpcMessage } from './sanitize';

/**
 * Re-writes a `text/event-stream` of JSON-RPC messages, sanitizing each `data:` payload.
 * Event framing (id / event / retry) is preserved so resumability (`Last-Event-ID`) keeps working.
 * Unparseable data is dropped, never passed through.
 */
export async function* transformSse(
  body: AsyncIterable<Uint8Array>,
  sanitize: (message: JsonRpcMessage) => JsonRpcMessage,
): AsyncGenerator<string> {
  const decoder = new TextDecoder();
  let buffer = '';

  const transformEvent = (raw: string): string => {
    const lines = raw.split(/\r?\n/);
    const data: string[] = [];
    const meta: string[] = [];
    for (const line of lines) {
      if (line.startsWith('data:')) {
        data.push(line.slice(5).replace(/^ /, ''));
      } else if (line.length > 0) {
        meta.push(line);
      }
    }
    if (data.length === 0) {
      return `${meta.join('\n')}\n\n`;
    }
    let payload: string;
    try {
      payload = JSON.stringify(sanitize(JSON.parse(data.join('\n'))));
    } catch {
      payload = '';
      meta.push(': non-JSON data dropped by anonymizing proxy');
    }

    return `${[...meta, ...(payload ? [`data: ${payload}`] : [])].join('\n')}\n\n`;
  };

  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    let boundary: RegExpExecArray | null;
    while ((boundary = /\r?\n\r?\n/.exec(buffer))) {
      const raw = buffer.slice(0, boundary.index);
      buffer = buffer.slice(boundary.index + boundary[0].length);
      yield transformEvent(raw);
    }
  }
  buffer += decoder.decode();
  if (buffer.trim()) {
    yield transformEvent(buffer);
  }
}

import { REDACTED_PLACEHOLDER, type Anonymizer } from '@epilot/anonymization';

export type SanitizerOptions = {
  anonymizer: Anonymizer;
  /** keys whose subtree is a bag of user properties -> strict anonymization */
  userPropertyKeys: RegExp;
  /** user property keys (lowercased) explicitly allowed through unchanged, e.g. `plan`, `role` */
  keepUserProperties?: string[];
  /** URLs on these hosts keep their query string (e.g. links back into the Fullstory app) */
  keepUrlHosts?: RegExp;
  /** pass image/audio/blob content through (cannot be anonymized). Default: false */
  allowBinaryContent?: boolean;
  /** tool visibility: default deny-list, optional allow-list */
  isToolBlocked: (name: string) => boolean;
};

export type JsonRpcMessage = {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
};

type ContentItem = { type?: string; [key: string]: unknown };

const URL_PATTERN = /\bhttps?:\/\/[^\s"'<>`)\]]+/g;
const PROSE_KEY_VALUE = /^(\s*(?:[-*]\s+)?\**)([A-Za-z_$][\w .$-]{0,60}?)(\**\s*[:=]\**\s*)(?!\/\/)(\S.*)$/;
const BINARY_PLACEHOLDER = '[binary content removed by anonymizing proxy]';

/** server-initiated methods whose params carry protocol data only */
const PROTOCOL_ONLY_METHODS = new Set([
  'ping',
  'notifications/progress',
  'notifications/cancelled',
  'notifications/initialized',
  'notifications/tools/list_changed',
  'notifications/resources/list_changed',
  'notifications/prompts/list_changed',
  'notifications/resources/updated',
]);

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export const createSanitizer = (options: SanitizerOptions) => {
  const { anonymizer, userPropertyKeys, keepUrlHosts, allowBinaryContent = false } = options;
  const keepUserProperties = new Set((options.keepUserProperties ?? []).map((key) => key.toLowerCase()));

  /** query strings / fragments routinely carry emails, tokens, search terms -> redact values, keep keys */
  const redactUrls = (text: string): string =>
    text.replace(URL_PATTERN, (match) => {
      let url: URL;
      try {
        url = new URL(match);
      } catch {
        return match;
      }
      if (keepUrlHosts?.test(url.hostname) || (!url.search && !url.hash)) {
        return match;
      }
      const keys = [...new Set(url.searchParams.keys())];
      url.search = keys.map((key) => `${encodeURIComponent(key)}=REDACTED`).join('&');
      url.hash = '';

      return url.toString();
    });

  /** user property bag: allow-listed keys raw, everything else strict (unknown strings redacted) */
  const sanitizeUserProperties = (node: unknown): unknown => {
    if (Array.isArray(node)) {
      return node.map(sanitizeUserProperties);
    }
    if (!isPlainObject(node)) {
      return anonymizer.anonymizeUnknown(node, { strict: true });
    }

    return Object.fromEntries(
      Object.entries(node).map(([key, value]) => {
        if (keepUserProperties.has(key.toLowerCase())) {
          return [key, value];
        }

        return [key, (anonymizer.anonymizeUnknown({ [key]: value }, { strict: true }) as Record<string, unknown>)[key]];
      }),
    );
  };

  const preWalk = (node: unknown): unknown => {
    if (typeof node === 'string') {
      return redactUrls(node);
    }
    if (Array.isArray(node)) {
      return node.map(preWalk);
    }
    if (!isPlainObject(node)) {
      return node;
    }

    return Object.fromEntries(
      Object.entries(node).map(([key, value]) => [
        key,
        userPropertyKeys.test(key) && value !== null && typeof value === 'object'
          ? sanitizeUserProperties(value)
          : preWalk(value),
      ]),
    );
  };

  /** arbitrary JSON: user-property bags strict, URLs de-queried, then field heuristics + pattern scrub */
  const sanitizeJson = (value: unknown): unknown => anonymizer.anonymizeUnknown(preWalk(value));

  /** `key: value` lines in markdown/prose output get the same field-name heuristics as JSON */
  const sanitizeProseLine = (line: string): string => {
    const match = PROSE_KEY_VALUE.exec(line);
    if (match) {
      const [, prefix, rawKey, separator, value] = match;
      const key = rawKey.trim().toLowerCase().replace(/[\s.-]+/g, '_');
      const input = userPropertyKeys.test(key) ? { [key]: { value } } : { [key]: value };
      const output = (sanitizeJson(input) as Record<string, unknown>)[key];
      const sanitized = isPlainObject(output) ? output.value : output;
      if (typeof sanitized === 'string') {
        return `${prefix}${rawKey}${separator}${sanitized}`;
      }
    }

    return anonymizer.scrub(redactUrls(line)) as string;
  };

  const sanitizeText = (text: string): string => {
    const trimmed = text.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const parsed: unknown = JSON.parse(trimmed);
        const indent = trimmed.includes('\n') ? 2 : undefined;

        return JSON.stringify(sanitizeJson(parsed), null, indent);
      } catch {
        // not JSON -> treat as prose
      }
    }

    return text.split('\n').map(sanitizeProseLine).join('\n');
  };

  const sanitizeContentItem = (item: ContentItem): ContentItem => {
    switch (item.type) {
      case 'text':
        return { ...item, text: typeof item.text === 'string' ? sanitizeText(item.text) : item.text };
      case 'image':
      case 'audio':
        return allowBinaryContent ? item : { type: 'text', text: BINARY_PLACEHOLDER };
      case 'resource': {
        const resource = isPlainObject(item.resource) ? item.resource : {};
        if (typeof resource.blob === 'string' && !allowBinaryContent) {
          return { type: 'text', text: BINARY_PLACEHOLDER };
        }

        return {
          ...item,
          resource: {
            ...resource,
            ...(typeof resource.uri === 'string' && { uri: redactUrls(resource.uri) }),
            ...(typeof resource.text === 'string' && { text: sanitizeText(resource.text) }),
          },
        };
      }
      case 'resource_link':
        return sanitizeJson(item) as ContentItem;
      default:
        // unknown content type: fail safe
        return { type: 'text', text: BINARY_PLACEHOLDER };
    }
  };

  const sanitizeContent = (content: unknown): unknown =>
    Array.isArray(content) ? content.map((item) => sanitizeContentItem(isPlainObject(item) ? item : {})) : content;

  const sanitizeResult = (result: Record<string, unknown>): Record<string, unknown> => {
    const out: Record<string, unknown> = { ...result };

    // tools/list: hide blocked tools so the model never plans with them
    if (Array.isArray(out.tools)) {
      out.tools = out.tools.filter(
        (tool) => !(isPlainObject(tool) && typeof tool.name === 'string' && options.isToolBlocked(tool.name)),
      );
    }
    // tools/call
    if ('content' in out) {
      out.content = sanitizeContent(out.content);
    }
    if ('structuredContent' in out) {
      out.structuredContent = sanitizeJson(out.structuredContent);
    }
    // resources/read
    if (Array.isArray(out.contents)) {
      out.contents = out.contents.map((entry) => sanitizeContentItem({ type: 'resource', resource: entry }).resource);
    }
    // prompts/get
    if (Array.isArray(out.messages)) {
      out.messages = out.messages.map((message) =>
        isPlainObject(message) && isPlainObject(message.content)
          ? { ...message, content: sanitizeContentItem(message.content) }
          : message,
      );
    }

    return out;
  };

  /** sanitize a single upstream -> client JSON-RPC message */
  const sanitizeMessage = (message: JsonRpcMessage): JsonRpcMessage => {
    if (!isPlainObject(message)) {
      return message;
    }
    if (isPlainObject(message.result)) {
      return { ...message, result: sanitizeResult(message.result) };
    }
    if (isPlainObject(message.error)) {
      return {
        ...message,
        error: {
          ...message.error,
          message: sanitizeText(String(message.error.message ?? '')),
          ...('data' in message.error && { data: sanitizeJson(message.error.data) }),
        },
      };
    }
    if (typeof message.method === 'string' && message.params && !PROTOCOL_ONLY_METHODS.has(message.method)) {
      return { ...message, params: sanitizeJson(message.params) as Record<string, unknown> };
    }

    return message;
  };

  const sanitizePayload = (payload: unknown): unknown =>
    Array.isArray(payload)
      ? payload.map((message) => sanitizeMessage(message as JsonRpcMessage))
      : sanitizeMessage(payload as JsonRpcMessage);

  return { sanitizePayload, sanitizeMessage, sanitizeText, sanitizeJson, redacted: REDACTED_PLACEHOLDER };
};

export type Sanitizer = ReturnType<typeof createSanitizer>;

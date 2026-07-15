import { DEFAULT_PII_FIELDS, SYSTEM_KEEP_KEYS, UNKNOWN_FIELD_HEURISTICS } from './defaults';
import { applyStrategy } from './entity';
import type { Pseudonymizer } from './pseudonymizer';
import { scrubStringLeaves } from './response';
import type { AnonymizationStrategy } from './types';
import { isPlainObject, mapEntries } from './utils';

/**
 * Non-schema-aware anonymization for arbitrary JSON: audit logs, integration monitoring
 * records, inbound webhook/ERP events — any context where no entity schema is available.
 *
 * Two layers:
 * 1. field-name heuristics: keys matching curated PII field names (`first_name`, `email`,
 *    `iban`, …) get the corresponding strategy applied to their values
 * 2. pattern scrubbing: emails / phone numbers / IBANs embedded in ALL remaining string
 *    leaves are replaced with pseudonyms (idempotent)
 *
 * `strict: true` additionally REDACTS every string leaf not explicitly recognized as safe —
 * use it where the payload must not retain any unclassified free text (e.g. long-retention
 * logs). Non-strict mode is best-effort by nature: heuristics cannot guarantee that novel
 * field names or unusual formats are caught. For entity data, always prefer the schema-aware
 * mode.
 */
export const anonymizeUnknown = (params: {
  value: unknown;
  pseudonymizer: Pseudonymizer;
  strict?: boolean;
  overrides?: Record<string, AnonymizationStrategy>;
}): unknown => {
  const { value, pseudonymizer, strict = false, overrides } = params;

  const fieldStrategy = (key: string): AnonymizationStrategy | undefined => {
    const normalized = key.toLowerCase();

    return (
      overrides?.[`*:${normalized}`] ?? DEFAULT_PII_FIELDS[`*:${normalized}`] ?? UNKNOWN_FIELD_HEURISTICS[normalized]
    );
  };

  const walk = (node: unknown): unknown => {
    if (typeof node === 'string') {
      return strict ? pseudonymizer.redact() : pseudonymizer.scrubText(node);
    }

    if (Array.isArray(node)) {
      return node.map(walk);
    }

    if (isPlainObject(node)) {
      return mapEntries(node, (val, key) => {
        if (SYSTEM_KEEP_KEYS.includes(key) || isIdentifierKey(key)) {
          return val;
        }

        const strategy = fieldStrategy(key);
        if (strategy) {
          return applyStrategy({ value: val, strategy, pseudonymizer });
        }

        return walk(val);
      });
    }

    return node;
  };

  return walk(value);
};

/**
 * Pattern-based scrubbing of any value: replaces emails / phone numbers / IBANs embedded in
 * every string leaf with deterministic pseudonyms. Structure, keys and non-string values are
 * untouched. Idempotent. The lightest-touch tool — use for log lines, error messages, event
 * envelopes.
 */
export const scrub = (params: { value: unknown; pseudonymizer: Pseudonymizer }): unknown =>
  scrubStringLeaves(params.value, params.pseudonymizer);

/** ids, timestamps and enum-ish keys that are safe to keep even in strict mode */
const isIdentifierKey = (key: string): boolean =>
  /(^|_)(id|ids|uuid|key|type|status|state|slug|schema|operation|timestamp|created_at|updated_at|org|org_id|user_id)$/i.test(
    key,
  );

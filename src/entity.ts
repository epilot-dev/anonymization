import {
  ADDRESS_KEEP_KEYS,
  DEFAULT_PII_FIELDS,
  PAYMENT_PSEUDONYMIZE_KEY_PATTERN,
  STRATEGY_BY_ATTRIBUTE_TYPE,
  SYSTEM_KEEP_KEYS,
  USER_FIELD_STRATEGY,
} from './defaults';
import type { Pseudonymizer } from './pseudonymizer';
import type { AnonymizationStrategy, Attribute, EntityLike, Schema } from './types';
import { isPlainObject, mapEntries } from './utils';

/**
 * Resolve the anonymization strategy for a single attribute.
 *
 * Precedence (first match wins):
 * 1. `data_classification: 'public'` on the schema attribute -> keep (org opt-out)
 * 2. `data_classification: 'pii'` on the schema attribute -> mask (org opt-in, e.g. free text)
 * 3. consumer `overrides` (same key format as the curated map)
 * 4. curated built-in PII fields (`DEFAULT_PII_FIELDS`)
 * 5. defaults by attribute type (email, phone, address, payment)
 * 6. keep
 */
export const getAttributeStrategy = (params: {
  slug: string;
  attributeName: string;
  attribute?: Attribute;
  overrides?: Record<string, AnonymizationStrategy>;
}): AnonymizationStrategy => {
  const { slug, attributeName, attribute, overrides } = params;

  if (attribute?.data_classification === 'public') {
    return 'keep';
  }

  if (attribute?.data_classification === 'pii') {
    const byType = attribute.type ? STRATEGY_BY_ATTRIBUTE_TYPE[attribute.type] : undefined;
    if (byType) {
      return byType;
    }
    if (attribute.type === 'date' || attribute.type === 'datetime') {
      return 'date_year';
    }

    // free text: multiline content is redacted, single-line values stay joinable
    return attribute.multiline ? 'redact' : 'value';
  }

  const configured =
    overrides?.[`${slug}:${attributeName}`] ??
    overrides?.[`*:${attributeName}`] ??
    DEFAULT_PII_FIELDS[`${slug}:${attributeName}`] ??
    DEFAULT_PII_FIELDS[`*:${attributeName}`];
  if (configured) {
    return configured;
  }

  const byType = attribute?.type ? STRATEGY_BY_ATTRIBUTE_TYPE[attribute.type] : undefined;

  return byType ?? 'keep';
};

/**
 * Anonymize a single entity (or partial entity, e.g. an activity diff) using its schema.
 *
 * Works on a copy; the input is never mutated. Values of attributes classified as PII are
 * pseudonymized/generalized/redacted; everything else is returned unchanged.
 */
export const anonymizeEntity = <T extends EntityLike>(params: {
  entity: T;
  schema?: Schema | null;
  slug?: string;
  pseudonymizer: Pseudonymizer;
  overrides?: Record<string, AnonymizationStrategy>;
}): T => {
  const { entity, schema, pseudonymizer, overrides } = params;
  const slug = params.slug ?? (entity?._schema as string) ?? schema?.slug ?? '*';

  if (!isPlainObject(entity)) {
    return entity;
  }

  const attributesByName = new Map<string, Attribute>((schema?.attributes ?? []).map((attr) => [attr.name, attr]));

  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(entity)) {
    // _title is computed from attributes and can carry PII (e.g. contact names)
    if (key === '_title') {
      const strategy = getAttributeStrategy({ slug, attributeName: '_title', overrides });
      result[key] = applyStrategy({ value, strategy, pseudonymizer });
      continue;
    }

    if (SYSTEM_KEEP_KEYS.includes(key)) {
      result[key] = value;
      continue;
    }

    const strategy = getAttributeStrategy({
      slug,
      attributeName: key,
      attribute: attributesByName.get(key),
      overrides,
    });
    result[key] = applyStrategy({ value, strategy, pseudonymizer });
  }

  return result as T;
};

/**
 * Apply an anonymization strategy to an attribute value, preserving the value's shape
 * (repeatable items keep their `_id`/`_tags`, relation metadata is preserved).
 */
export const applyStrategy = (params: {
  value: unknown;
  strategy: AnonymizationStrategy;
  pseudonymizer: Pseudonymizer;
}): unknown => {
  const { value, strategy, pseudonymizer } = params;

  if (strategy === 'keep' || value === null || value === undefined) {
    return value;
  }

  switch (strategy) {
    case 'address':
      return mapValue(value, (item) => anonymizeAddressItem(item, pseudonymizer));
    case 'payment':
      return mapValue(value, (item) => anonymizePaymentItem(item, pseudonymizer));
    case 'user':
      return mapValue(value, (item) => anonymizeUserItem(item, pseudonymizer));
    case 'consent':
      return mapValue(value, (item) => anonymizeConsentItem(item, pseudonymizer));
    case 'date_year':
      return mapStringLeaves(value, (str) => pseudonymizer.dateToYear(str));
    case 'redact':
      return mapStringLeaves(value, () => pseudonymizer.redact());
    default:
      return mapStringLeaves(value, (str) => pseudonymizer[strategy](str));
  }
};

/** Apply fn to arrays item-wise, otherwise to the value itself */
const mapValue = (value: unknown, fn: (item: unknown) => unknown): unknown =>
  Array.isArray(value) ? value.map(fn) : fn(value);

/**
 * Apply fn to every string leaf of a value, preserving structure and system keys.
 * Handles plain strings, repeatable items ({ _id, _tags, email: "..." }) and nested objects.
 */
export const mapStringLeaves = (value: unknown, fn: (str: string) => string): unknown => {
  if (typeof value === 'string') {
    return value ? fn(value) : value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => mapStringLeaves(item, fn));
  }

  if (isPlainObject(value)) {
    return mapEntries(value, (val, key) => (SYSTEM_KEEP_KEYS.includes(key) ? val : mapStringLeaves(val, fn)));
  }

  return value;
};

/**
 * Generalize an address: keep quasi-identifiers useful for analysis
 * (postal code, city, country), pseudonymize the street, drop the rest.
 */
const anonymizeAddressItem = (item: unknown, pseudonymizer: Pseudonymizer): unknown => {
  if (typeof item === 'string') {
    return pseudonymizer.street(item);
  }

  if (!isPlainObject(item)) {
    return item;
  }

  return Object.fromEntries(
    Object.entries(item).flatMap(([key, val]) => {
      if (ADDRESS_KEEP_KEYS.includes(key)) {
        return [[key, val]];
      }
      if (key === 'street' && typeof val === 'string') {
        // include the street number in the derivation so identical streets with
        // different house numbers map to different pseudonyms
        return [[key, pseudonymizer.street(`${val} ${(item as Record<string, unknown>).street_number ?? ''}`.trim())]];
      }
      if (key === 'street_number') {
        return []; // dropped: too identifying in combination with street
      }

      return [[key, mapStringLeaves(val, () => pseudonymizer.redact())]];
    }),
  );
};

/**
 * Scrub payment details: pseudonymize account/holder identifiers (IBAN keeps its own
 * deterministic form), keep non-identifying bank metadata (bank name, BIC, type).
 */
const anonymizePaymentItem = (item: unknown, pseudonymizer: Pseudonymizer): unknown => {
  if (typeof item === 'string') {
    return pseudonymizer.value(item);
  }

  if (Array.isArray(item)) {
    return item.map((i) => anonymizePaymentItem(i, pseudonymizer));
  }

  if (!isPlainObject(item)) {
    return item;
  }

  return mapEntries(item, (val, key) => {
    if (SYSTEM_KEEP_KEYS.includes(key)) {
      return val;
    }
    if (isPlainObject(val) || Array.isArray(val)) {
      return anonymizePaymentItem(val, pseudonymizer);
    }
    if (typeof val === 'string' && PAYMENT_PSEUDONYMIZE_KEY_PATTERN.test(key)) {
      return key.toLowerCase().includes('iban') ? pseudonymizer.iban(val) : pseudonymizer.value(val);
    }

    return val;
  });
};

/**
 * Anonymize an embedded epilot user object (user-relation attributes such as `contact_owner`).
 * Pseudonymizes name/email fields and REDACTS credentials (`token`, `password`, `secret`, …),
 * while keeping non-identifying operational metadata (ids, status, language, notification
 * settings, timestamps). Rules are applied by key at every nesting depth.
 */
const anonymizeUserItem = (item: unknown, pseudonymizer: Pseudonymizer): unknown => {
  if (typeof item === 'string') {
    return pseudonymizer.person(item);
  }

  if (Array.isArray(item)) {
    return item.map((i) => anonymizeUserItem(i, pseudonymizer));
  }

  if (!isPlainObject(item)) {
    return item;
  }

  return mapEntries(item, (val, key) => {
    if (SYSTEM_KEEP_KEYS.includes(key)) {
      return val;
    }

    const strategy = USER_FIELD_STRATEGY[key.toLowerCase()];
    if (strategy) {
      return applyStrategy({ value: val, strategy, pseudonymizer });
    }

    // recurse so a sensitive key nested deeper (e.g. token inside a settings object) is caught
    if (isPlainObject(val) || Array.isArray(val)) {
      return anonymizeUserItem(val, pseudonymizer);
    }

    return val;
  });
};

/** keys inside a consent value that hold the contact identifier the consent is keyed on */
const CONSENT_IDENTIFIER_KEYS = ['identifier', 'email', 'phone'];

/** pseudonymize a contact identifier string, preserving whether it reads as email or phone */
const pseudonymizeIdentifier = (value: string, pseudonymizer: Pseudonymizer): string => {
  if (value.includes('@')) {
    return pseudonymizer.email(value);
  }
  if (/^[+0-9][\d\s\-/()]*\d$/.test(value)) {
    return pseudonymizer.phone(value);
  }

  return pseudonymizer.value(value);
};

/**
 * Anonymize a consent value (consent attributes such as `consent_email_marketing`).
 * Pseudonymizes the contact identifier(s) the consent is keyed on (email or phone), keeps the
 * consent status and event structure, and scrubs identifiers embedded elsewhere in the value.
 */
const anonymizeConsentItem = (item: unknown, pseudonymizer: Pseudonymizer): unknown => {
  // consent identifiers can be stored as bare strings (`identifiers: string[]`)
  if (typeof item === 'string') {
    return pseudonymizeIdentifier(item, pseudonymizer);
  }

  if (Array.isArray(item)) {
    return item.map((i) => anonymizeConsentItem(i, pseudonymizer));
  }

  if (!isPlainObject(item)) {
    return item;
  }

  return mapEntries(item, (val, key) => {
    if (SYSTEM_KEEP_KEYS.includes(key)) {
      return val;
    }
    if (CONSENT_IDENTIFIER_KEYS.includes(key.toLowerCase()) && typeof val === 'string') {
      return pseudonymizeIdentifier(val, pseudonymizer);
    }
    if (isPlainObject(val) || Array.isArray(val)) {
      return anonymizeConsentItem(val, pseudonymizer);
    }
    // scrub any identifier embedded in remaining free text (e.g. event payloads)
    if (typeof val === 'string') {
      return pseudonymizer.scrubText(val);
    }

    return val;
  });
};

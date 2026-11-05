import { createHmac } from 'crypto';

import { PSEUDONYM_EMAIL_DOMAIN, REDACTED_PLACEHOLDER } from './defaults';
import type { AnonymizerLogger } from './types';
import { replaceIban, scrubStreets, scrubWithUrls, type ValueReplacers } from './value-detection';

/**
 * Deterministic, one-way pseudonymization of PII values.
 *
 * Pseudonyms are derived with `HMAC-SHA256(secret, orgId + kind + normalized(value))`, so:
 * - the same value always maps to the same pseudonym within an org — joins, grouping and
 *   deduplication keep working across requests, services, and time
 * - pseudonyms differ across orgs — no cross-tenant correlation
 * - the mapping cannot be reversed without the secret (Kerckhoffs's principle: this code is
 *   public; all security rests on the secret you inject)
 *
 * FAIL-SAFE: when no secret is configured, every value is replaced with the static redaction
 * placeholder. The library never silently passes raw values through.
 */
export type Pseudonymizer = {
  person: (value: string) => string;
  company: (value: string) => string;
  email: (value: string) => string;
  phone: (value: string) => string;
  iban: (value: string) => string;
  value: (value: string) => string;
  text: (value: string) => string;
  street: (value: string) => string;
  dateToYear: (value: string) => string;
  redact: (value?: unknown) => string;
  /**
   * replaces emails / phone numbers / IBANs / street addresses embedded in free text, and the
   * place + precise position of map links (URL components are decoded first); idempotent
   */
  scrubText: (value: string) => string;
};

export const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
export const IBAN_PATTERN = /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9][ ]?){11,30}\b/g;
// International: "+49 170 1234567", "0049 170 1234567". The "00" form only at a token start,
// so digit runs inside ids, timestamps or amounts ("1729700123456") are left alone.
export const PHONE_PATTERN = /(?:\+|(?<![\w.])00)[1-9][\d\s\-/()]{6,}\d/g;
// National (German/Austrian) format: trunk prefix 0 + area code, then a separator:
// "030 1234567", "0221/123456", "0170-1234567", "(0221) 123 456". The separator keeps bare
// digit runs (ids, postal codes) out; "0[1-9]" keeps the "+00 000 …" pseudonyms from re-matching.
export const NATIONAL_PHONE_PATTERN =
  /(?<![\w.:/-])(?:0[1-9]\d{1,4}[\s/-]|\(0[1-9]\d{1,4}\)\s?)\d{3,}(?:[\s-]\d+)*(?![\w:/-]|\.\d)/g;

export const createPseudonymizer = (params: {
  orgId: string;
  secret?: string;
  logger?: AnonymizerLogger;
}): Pseudonymizer => {
  const { orgId, secret, logger } = params;

  if (!secret) {
    logger?.warn?.('@epilot/anonymization: no secret configured - falling back to static redaction');

    const redact = () => REDACTED_PLACEHOLDER;

    return {
      person: redact,
      company: redact,
      email: redact,
      phone: redact,
      iban: redact,
      value: redact,
      text: redact,
      street: redact,
      dateToYear: redact,
      redact,
      // still scrub identifiers OUT of free text (replacing only the matched substrings),
      // rather than blanking the whole string — so the catch-all pass keeps non-PII text intact
      scrubText: makeScrubText({ email: redact, iban: redact, phone: redact, street: redact, value: redact }),
    };
  }

  const hash = (kind: string, value: string): string =>
    createHmac('sha256', secret).update(`${orgId}:${kind}:${normalize(value)}`).digest('hex').slice(0, 8);

  const pseudonymize = (kind: string, prefix: string) => (value: string) => `${prefix}_${hash(kind, value)}`;

  const email = (value: string) => `${hash('email', value)}@${PSEUDONYM_EMAIL_DOMAIN}`;
  // "+00 000 <digits>" cannot re-match PHONE_PATTERN (no "00" pair is followed by a nonzero
  // digit with enough tail), which keeps scrubText idempotent without a fragile guard
  const phone = (value: string) =>
    `+00 000 ${parseInt(hash('phone', value), 16).toString().slice(0, 8).padStart(8, '0')}`;
  const iban = pseudonymize('iban', 'iban');
  const street = pseudonymize('street', 'street');
  const value = pseudonymize('value', 'value');

  return {
    person: pseudonymize('person', 'person'),
    company: pseudonymize('company', 'company'),
    email,
    phone,
    iban,
    value,
    text: pseudonymize('text', 'title'),
    street,
    dateToYear: (value: string) => {
      const year = new Date(value).getFullYear();

      return Number.isFinite(year) ? `${year}-01-01` : REDACTED_PLACEHOLDER;
    },
    redact: () => REDACTED_PLACEHOLDER,
    scrubText: makeScrubText({ email, iban, phone, street, value }),
  };
};

type ScrubReplacers = ValueReplacers & {
  email: (value: string) => string;
  iban: (value: string) => string;
  phone: (value: string) => string;
};

/** A complete UUID: a fixed-format random token that cannot hold PII, so detectors never scan inside it. */
const UUID_TOKEN = /(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])/gi;
// One private-use code point per UUID: no detector matches it, it holds no digit, `@` or `/`.
const KEPT_FIRST = 0xe100;
const KEPT_LAST = 0xefff;
const KEPT_MARK = /[\ue100-\uefff]/g;
const HAS_KEPT_MARK = /[\ue100-\uefff]/;

/** Runs `scan` with every UUID swapped for a marker, then puts the UUIDs back. */
const withUuidsKept = (value: string, scan: (masked: string) => string): string => {
  // Text that already holds marker code points is scanned as-is, so restoring never mixes them up.
  if (!value.includes('-') || HAS_KEPT_MARK.test(value)) {
    return scan(value);
  }
  const kept: string[] = [];
  const masked = value.replace(UUID_TOKEN, (uuid) =>
    KEPT_FIRST + kept.length > KEPT_LAST ? uuid : String.fromCharCode(KEPT_FIRST + kept.push(uuid) - 1),
  );
  if (kept.length === 0) {
    return scan(value);
  }
  return scan(masked).replace(KEPT_MARK, (mark) => kept[mark.charCodeAt(0) - KEPT_FIRST]);
};

/** Every detector needs an `@` (emails), a `/` (URLs) or a digit (IBANs, phones, house numbers) */
const SCRUB_CANDIDATE = /[@/\d]/;

/**
 * Build a text scrubber that replaces email / IBAN / phone / street-address substrings embedded
 * in free text, leaving the rest of the string intact. Embedded URLs are decoded and scrubbed
 * per component; map links lose the place and precise position (see value-detection.ts).
 * The replacers are the pseudonymizer's own (or the redactor when no secret is configured).
 * Idempotent: pseudonymized emails are skipped, and the other pseudonyms do not re-match.
 */
const makeScrubText = (replacers: ScrubReplacers) => {
  const { email, iban, phone } = replacers;

  const scrubPlain = (value: string, context?: 'path'): string =>
    withUuidsKept(value, (masked) => scrubDetectors(masked, context));

  const scrubDetectors = (value: string, context?: 'path'): string => {
    // Cheap prefilters, so the bulk of strings in a large response (enums, labels, numbers,
    // timestamps) skip the full patterns: emails need an `@`, and every IBAN / phone match
    // contains a NUMBER_CANDIDATE match (see below).
    const hasAt = value.includes('@');
    const hasNumber = NUMBER_CANDIDATE.test(value);

    let result = hasAt
      ? value.replace(EMAIL_PATTERN, (match) => (match.endsWith(`@${PSEUDONYM_EMAIL_DOMAIN}`) ? match : email(match)))
      : value;
    if (hasNumber) {
      result = result.replace(IBAN_PATTERN, (match) => replaceIban(match, iban));
      if (context !== 'path') {
        result = result.replace(PHONE_PATTERN, phone).replace(NATIONAL_PHONE_PATTERN, phone);
      }
    }

    return scrubStreets(result, replacers);
  };

  return (value: string): string => (SCRUB_CANDIDATE.test(value) ? scrubWithUrls(value, scrubPlain, replacers) : value);
};

/**
 * Necessary condition for IBAN_PATTERN / PHONE_PATTERN / NATIONAL_PHONE_PATTERN: the prefix
 * each of them must start with (same lookbehinds). A superset by construction — it may let
 * through strings without a match, never skip one. Timestamps and plain numbers do not match.
 */
export const NUMBER_CANDIDATE = /[A-Z]{2}\d\d|\+[1-9]|(?<![\w.])00[1-9]|(?<![\w.:/-])\(?0[1-9]/;

const normalize = (value: string) => value.trim().toLowerCase();

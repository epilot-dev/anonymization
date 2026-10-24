import { createHmac } from 'crypto';

import { PSEUDONYM_EMAIL_DOMAIN, REDACTED_PLACEHOLDER } from './defaults';
import type { AnonymizerLogger } from './types';

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
  /** replaces emails / phone numbers / IBANs embedded in free text; idempotent */
  scrubText: (value: string) => string;
};

const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const IBAN_PATTERN = /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9][ ]?){11,30}\b/g;
// International: "+49 170 1234567", "0049 170 1234567". The "00" form only at a token start,
// so digit runs inside ids, timestamps or amounts ("1729700123456") are left alone.
const PHONE_PATTERN = /(?:\+|(?<![\w.])00)[1-9][\d\s\-/()]{6,}\d/g;
// National (German/Austrian) format: trunk prefix 0 + area code, then a separator:
// "030 1234567", "0221/123456", "0170-1234567", "(0221) 123 456". The separator keeps bare
// digit runs (ids, postal codes) out; "0[1-9]" keeps the "+00 000 …" pseudonyms from re-matching.
const NATIONAL_PHONE_PATTERN =
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
      scrubText: makeScrubText(redact, redact, redact),
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

  return {
    person: pseudonymize('person', 'person'),
    company: pseudonymize('company', 'company'),
    email,
    phone,
    iban,
    value: pseudonymize('value', 'value'),
    text: pseudonymize('text', 'title'),
    street: pseudonymize('street', 'street'),
    dateToYear: (value: string) => {
      const year = new Date(value).getFullYear();

      return Number.isFinite(year) ? `${year}-01-01` : REDACTED_PLACEHOLDER;
    },
    redact: () => REDACTED_PLACEHOLDER,
    scrubText: makeScrubText(email, iban, phone),
  };
};

/**
 * Build a text scrubber that replaces email / IBAN / phone substrings embedded in free text,
 * leaving the rest of the string intact. `email`/`iban`/`phone` are the pseudonymizer's own
 * replacers (or the redactor when no secret is configured). Idempotent: pseudonymized emails
 * are skipped, and phone/IBAN pseudonyms do not re-match the patterns.
 */
const makeScrubText =
  (email: (v: string) => string, iban: (v: string) => string, phone: (v: string) => string) => (value: string) =>
    value
      .replace(EMAIL_PATTERN, (match) => (match.endsWith(`@${PSEUDONYM_EMAIL_DOMAIN}`) ? match : email(match)))
      .replace(IBAN_PATTERN, iban)
      .replace(PHONE_PATTERN, phone)
      .replace(NATIONAL_PHONE_PATTERN, phone);

const normalize = (value: string) => value.trim().toLowerCase();

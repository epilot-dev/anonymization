import { describe, expect, it, vi } from 'vitest';

import { createAnonymizer } from './index';
import { IBAN_PATTERN, NATIONAL_PHONE_PATTERN, NUMBER_CANDIDATE, PHONE_PATTERN } from './pseudonymizer';
import type { Schema } from './types';

// Guards for the hot-path optimizations: they must not change what gets masked.

const matches = (pattern: RegExp, value: string) => new RegExp(pattern.source, pattern.flags.replace('g', '')).test(value);

describe('NUMBER_CANDIDATE prefilter', () => {
  const samples = [
    '+49 170 1234567',
    '0049 170 1234567',
    '0170-1234567',
    '030 1234567',
    '0221/123456',
    '(0221) 123 456',
    'Tel.: 0221 123456',
    'DE89370400440532013000',
    'DE89 3704 0044 0532 0130 00',
    'iban DE89370400440532013000 for Max',
    '2026-01-01T00:00:00Z',
    '1.5',
    'v2026.10.30',
    'Zähler 12345678',
    'Order 00123',
  ];

  // deterministic pseudo-random strings over the characters the patterns care about
  const alphabet = '0123456789 +-/().:ADEZx_';
  let seed = 42;
  const rand = () => {
    seed = (seed * 1103515245 + 12345) % 2 ** 31;

    return seed / 2 ** 31;
  };
  for (let i = 0; i < 20_000; i++) {
    const length = 4 + Math.floor(rand() * 24);
    samples.push(Array.from({ length }, () => alphabet[Math.floor(rand() * alphabet.length)]).join(''));
  }

  it('is a superset of the IBAN and phone patterns (never skips a match)', () => {
    const missed = samples.filter(
      (value) =>
        (matches(IBAN_PATTERN, value) || matches(PHONE_PATTERN, value) || matches(NATIONAL_PHONE_PATTERN, value)) &&
        !NUMBER_CANDIDATE.test(value),
    );

    expect(missed).toEqual([]);
  });

  it('lets timestamps and plain numbers skip the patterns', () => {
    for (const value of ['2026-01-01T00:00:00Z', '1.5', '42', '2026-10-30', 'v2026.10.30']) {
      expect(NUMBER_CANDIDATE.test(value)).toBe(false);
    }
  });
});

describe('anonymizeResponse on large responses', () => {
  const anonymizer = createAnonymizer({ orgId: '123', secret: 'test-secret' });
  const schema: Schema = {
    slug: 'contact',
    attributes: [
      { name: 'first_name', type: 'string' },
      { name: 'tags_json', type: 'json' },
    ],
  };

  const body = () => ({
    results: Array.from({ length: 50 }, (_, i) => ({
      _id: `c${i}`,
      _org: '123',
      _schema: 'contact',
      first_name: 'Max',
      tags_json: { labels: ['a', 'b'], nested: { note: `call +49 170 123456${i % 10}` } },
      meta: { source: 'import', counts: [1, 2, 3] },
    })),
    meta: { took: 5, note: 'mail max@example.com' },
  });

  it('resolves each distinct schema once', async () => {
    const schemaResolver = vi.fn(async () => schema);

    await anonymizer.anonymizeResponse(body(), { schemaResolver });

    expect(schemaResolver).toHaveBeenCalledTimes(1);
  });

  it('never mutates the input (unchanged subtrees may be shared)', async () => {
    const input = body();
    const snapshot = JSON.parse(JSON.stringify(input));

    const result = await anonymizer.anonymizeResponse(input, { schemaResolver: async () => schema });

    expect(input).toEqual(snapshot);
    expect(result.results[0].first_name).toMatch(/^person_/);
    expect(result.results[0].tags_json.nested.note).not.toContain('123456');
    expect(result.meta.note).not.toContain('max@example.com');
  });

  it('produces the same output for the same input across calls (classification cache is per call)', async () => {
    const first = await anonymizer.anonymizeResponse(body(), { schemaResolver: async () => schema });
    const second = await anonymizer.anonymizeResponse(body(), { schemaResolver: async () => null });

    // without a schema, `first_name` is still masked by the curated default
    expect(second.results[0].first_name).toBe(first.results[0].first_name);
  });
});

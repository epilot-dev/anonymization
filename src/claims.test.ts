import { describe, expect, it } from 'vitest';

import { hasAnonymizeClaim } from './claims';

describe('hasAnonymizeClaim', () => {
  it('detects the claim in boolean and stringified forms (authorizer contexts stringify)', () => {
    expect(hasAnonymizeClaim({ anonymize: true })).toBe(true);
    expect(hasAnonymizeClaim({ anonymize: 'true' })).toBe(true);
    expect(hasAnonymizeClaim({ anonymize: '1' })).toBe(true);
  });

  it('never turns anonymization on by accident', () => {
    expect(hasAnonymizeClaim({})).toBe(false);
    expect(hasAnonymizeClaim(null)).toBe(false);
    expect(hasAnonymizeClaim(undefined)).toBe(false);
    expect(hasAnonymizeClaim({ anonymize: false })).toBe(false);
    expect(hasAnonymizeClaim({ anonymize: 'false' })).toBe(false);
    expect(hasAnonymizeClaim({ anonymize: 0 })).toBe(false);
  });
});

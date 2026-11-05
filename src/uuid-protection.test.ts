import { randomUUID } from 'crypto';
import { describe, expect, it } from 'vitest';
import { createAnonymizer } from './index';

const anon = createAnonymizer({ orgId: 'o1', secret: 's' });
const scrub = (v: string) => anon.scrub(v) as string;

describe('UUIDs in scrubbed text', () => {
  it('stay intact, alone or inside longer ids', () => {
    for (const id of [
      '409cd08e-512e-4077-825e-001030608345',
      '3bef5002-8369-421b-8984-bc438db0538a',
      'loop-edge-881ab2e3-0029-4209-8f68-bd447103372c',
      '534063D5-084A-467A-8E8F-0036458494AA',
    ])
      expect(scrub(id)).toBe(id);
    for (let i = 0; i < 20000; i++) {
      const id = randomUUID();
      expect(scrub(id)).toBe(id);
    }
  });

  it('do not shield PII next to them', () => {
    const out = scrub('Ticket 409cd08e-512e-4077-825e-001030608345: call +49 30 1234567, IBAN DE89370400440532013000');
    expect(out).toMatch(/^Ticket 409cd08e-512e-4077-825e-001030608345: call \+00 000 \d{8}, IBAN iban_[0-9a-f]{8}$/);
  });

  it('stay intact in URLs while the URL is still scrubbed', () => {
    const out = scrub('https://app.example.com/flows/409cd08e-512e-4077-825e-001030608345?mail=max%40stadtwerke-x.de');
    expect(out).toContain('/flows/409cd08e-512e-4077-825e-001030608345');
    expect(out).not.toContain('stadtwerke-x.de');
  });

  it('keep scrubbing idempotent and leave text with marker characters alone', () => {
    const once = scrub('id 409cd08e-512e-4077-825e-001030608345 tel +49 30 1234567');
    expect(scrub(once)).toBe(once);
    const odd = ' 409cd08e-512e-4077-825e-001030608345 +49 30 1234567';
    expect(scrub(odd)).toContain('+00 000');
  });
});

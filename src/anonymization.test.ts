import { describe, expect, it } from 'vitest';

import { createAnonymizer } from './index';
import type { Schema } from './types';

const anonymizer = createAnonymizer({ orgId: '123', secret: 'test-secret' });

const contactSchema: Schema = {
  slug: 'contact',
  attributes: [
    { name: 'first_name', type: 'string' },
    { name: 'last_name', type: 'string' },
    { name: 'birthdate', type: 'date' },
    { name: 'email', type: 'email' },
    { name: 'phone', type: 'phone' },
    { name: 'address', type: 'address' },
    { name: 'payment', type: 'payment' },
    { name: 'status', type: 'select' },
    { name: 'notes', type: 'string', multiline: true },
    { name: 'secret_notes', type: 'string', multiline: true, data_classification: 'pii' },
    { name: 'customer_number', type: 'string', data_classification: 'pii' },
    { name: 'tariff_email', type: 'email', data_classification: 'public' },
  ],
};

const contact = {
  _id: 'e1',
  _org: '123',
  _schema: 'contact',
  _title: 'Max Mustermann',
  _tags: ['vip'],
  first_name: 'Max',
  last_name: 'Mustermann',
  birthdate: '1985-06-14',
  email: [{ _id: 'i1', _tags: ['primary'], email: 'max@example.com' }],
  phone: [{ phone: '+49 170 1234567' }],
  address: [
    {
      _id: 'a1',
      street: 'Musterstr.',
      street_number: '12b',
      postal_code: '50667',
      city: 'Köln',
      country: 'DE',
      additional_info: 'c/o Mustermann',
    },
  ],
  payment: [{ type: 'payment_sepa', data: { iban: 'DE89370400440532013000', bank_name: 'Test Bank', bic: 'COBADEFF' } }],
  status: 'active',
  notes: 'Called about tariff change',
  secret_notes: 'Divorced, two kids',
  customer_number: 'KD-100234',
  tariff_email: 'tariffs@energy.example',
};

describe('anonymizeEntity (schema-aware)', () => {
  const result = anonymizer.anonymizeEntity({ entity: contact, schema: contactSchema }) as any;

  it('keeps system metadata and non-PII values', () => {
    expect(result._id).toBe('e1');
    expect(result._tags).toEqual(['vip']);
    expect(result.status).toBe('active');
    expect(result.notes).toBe('Called about tariff change'); // free text is opt-in
  });

  it('pseudonymizes identifiers deterministically per org', () => {
    expect(result.first_name).toMatch(/^person_[0-9a-f]{8}$/);
    expect(result._title).toBe(result.first_name.replace(result.first_name, result._title)); // stable format
    expect(result.email[0].email).toMatch(/^[0-9a-f]{8}@anonymized\.invalid$/);
    expect(result.phone[0].phone).toMatch(/^\+00 000 \d{8}$/);

    const again = anonymizer.anonymizeEntity({ entity: contact, schema: contactSchema }) as any;
    expect(again.first_name).toBe(result.first_name);

    const otherOrg = createAnonymizer({ orgId: '456', secret: 'test-secret' });
    expect((otherOrg.anonymizeEntity({ entity: contact, schema: contactSchema }) as any).first_name).not.toBe(
      result.first_name,
    );
  });

  it('generalizes addresses and birthdates, scrubs payments', () => {
    expect(result.address[0]).toMatchObject({ postal_code: '50667', city: 'Köln', country: 'DE' });
    expect(result.address[0].street).toMatch(/^street_/);
    expect(result.address[0].street_number).toBeUndefined();
    expect(result.address[0].additional_info).toBe('[REDACTED]');
    expect(result.birthdate).toBe('1985-01-01');
    expect(result.payment[0].data.iban).toMatch(/^iban_/);
    expect(result.payment[0].data.bank_name).toBe('Test Bank');
  });

  it('honors data_classification pii/public', () => {
    expect(result.secret_notes).toBe('[REDACTED]');
    expect(result.customer_number).toMatch(/^value_/);
    expect(result.tariff_email).toBe('tariffs@energy.example');
  });

  it('applies curated defaults without a schema', () => {
    const opportunity = anonymizer.anonymizeEntity({
      entity: {
        _id: 'o1',
        _schema: 'opportunity',
        _title: 'PV Anlage Max Mustermann',
        description: 'call back at +49 170 1234567',
        source: 'journey',
      },
    }) as any;
    expect(opportunity._title).toMatch(/^title_/);
    expect(opportunity.description).toBe('[REDACTED]');
    expect(opportunity.source).toBe('journey');
  });

  it('supports consumer overrides', () => {
    const custom = createAnonymizer({
      orgId: '123',
      secret: 'test-secret',
      overrides: { 'mycustom:internal_note': 'redact' },
    });
    const result = custom.anonymizeEntity({
      entity: { _id: 'x', _schema: 'mycustom', internal_note: 'Max was here', other: 'kept' },
    }) as any;
    expect(result.internal_note).toBe('[REDACTED]');
    expect(result.other).toBe('kept');
  });
});

describe('user-relation attributes (type relation_user)', () => {
  const schema: Schema = {
    slug: 'contact',
    attributes: [{ name: 'contact_owner', type: 'relation_user' }],
  };
  // shape observed leaking in production: an embedded epilot user object with an auth token
  const entity = {
    _id: 'c1',
    _org: '739224',
    _schema: 'contact',
    contact_owner: [
      {
        id: '10002602',
        email: 'zsoltssolyom+user1@gmail.com',
        display_name: 'Zsolt user',
        token: '90359967-d521-424d-9140-d863dea2706a',
        organization_id: '739224',
        preferred_language: 'de',
        status: 'Active',
        email_notification_setting: { assigned_task: true, created_task: true },
        created_at: '2020-11-06T16:31:37.705261',
      },
    ],
  };

  it('pseudonymizes name/email, REDACTS the token, keeps ids and metadata', () => {
    const owner = (anonymizer.anonymizeEntity({ entity, schema }) as any).contact_owner[0];
    expect(owner.email).toMatch(/@anonymized\.invalid$/);
    expect(owner.email).not.toContain('zsolt');
    expect(owner.display_name).toMatch(/^person_/);
    expect(owner.token).toBe('[REDACTED]'); // credential must never pass through
    // non-PII operational metadata preserved for assignment logic
    expect(owner.id).toBe('10002602');
    expect(owner.organization_id).toBe('739224');
    expect(owner.status).toBe('Active');
    expect(owner.preferred_language).toBe('de');
    expect(owner.email_notification_setting).toEqual({ assigned_task: true, created_task: true });
    expect(owner.created_at).toBe('2020-11-06T16:31:37.705261');
  });

  it('is caught by curated name fallback even without a schema', () => {
    const owner = (anonymizer.anonymizeEntity({ entity, schema: null }) as any).contact_owner[0];
    expect(owner.email).toMatch(/@anonymized\.invalid$/);
    expect(owner.token).toBe('[REDACTED]');
  });
});

describe('fail-safe without secret', () => {
  it('redacts instead of pseudonymizing', () => {
    const noSecret = createAnonymizer({ orgId: '123' });
    const result = noSecret.anonymizeEntity({ entity: contact, schema: contactSchema }) as any;
    expect(result.first_name).toBe('[REDACTED]');
    expect(result.email[0].email).toBe('[REDACTED]');
    expect(result.status).toBe('active');
  });
});

describe('anonymizeResponse (schema-aware walker)', () => {
  const schemaResolver = async ({ slug }: { slug: string }) => (slug === 'contact' ? contactSchema : null);

  it('anonymizes entities in search results and hydrated relations', async () => {
    const body = {
      hits: 1,
      results: [
        {
          _id: 'order-1',
          _org: '123',
          _schema: 'order',
          _title: 'ORD-100',
          customer: [{ $relation: { entity_id: 'e1' }, _id: 'e1', _org: '123', _schema: 'contact', first_name: 'Max' }],
        },
      ],
    };
    const result = (await anonymizer.anonymizeResponse(body, { schemaResolver })) as any;
    expect(result.results[0]._title).toBe('ORD-100');
    expect(result.results[0].customer[0].first_name).toMatch(/^person_/);
    expect(result.results[0].customer[0].$relation).toEqual({ entity_id: 'e1' });
  });

  it('anonymizes activity operations: payload, diff, caller, embedded PII', async () => {
    const body = {
      results: [
        {
          type: 'EntityUpdated',
          title: 'Entity updated',
          message: 'updated by max@example.com',
          caller: { user_id: 'u1', name: 'Max Mustermann', email: 'max@example.com' },
          operations: [
            {
              activity_id: 'act-1',
              operation: 'updateEntity',
              params: { id: 'e1', slug: 'contact' },
              payload: { _schema: 'contact', _org: '123', first_name: 'Erika', status: 'active' },
              diff: { updated: { first_name: 'Max' } },
            },
          ],
        },
      ],
    };
    const result = (await anonymizer.anonymizeResponse(body, { schemaResolver })) as any;
    const activity = result.results[0];
    expect(activity.message).not.toContain('max@example.com');
    expect(activity.caller.name).toMatch(/^person_/);
    expect(activity.caller.user_id).toBe('u1');
    expect(activity.operations[0].payload.first_name).toMatch(/^person_/);
    expect(activity.operations[0].payload.status).toBe('active');
    expect(activity.operations[0].diff.updated.first_name).toMatch(/^person_/);
  });

  it('is fail-safe when the schema resolver throws', async () => {
    const failing = async () => {
      throw new Error('unavailable');
    };
    const body = { entity: { _id: 'e1', _org: '123', _schema: 'contact', first_name: 'Max', status: 'active' } };
    const result = (await anonymizer.anonymizeResponse(body, { schemaResolver: failing })) as any;
    expect(result.entity.first_name).toMatch(/^person_/); // curated default by field name
    expect(result.entity.status).toBe('active');
  });
});

describe('non-schema-aware mode', () => {
  it('scrub replaces embedded emails/phones/IBANs, idempotently', () => {
    const value = { log: 'user max@example.com paid from DE89370400440532013000, call +49 170 1234567', count: 3 };
    const once = anonymizer.scrub(value) as any;
    expect(once.log).not.toContain('max@example.com');
    expect(once.log).not.toContain('DE8937');
    expect(once.log).not.toContain('170');
    expect(once.count).toBe(3);
    expect(anonymizer.scrub(once)).toEqual(once);
  });

  it('anonymizeUnknown applies field-name heuristics', () => {
    const event = {
      event_type: 'contact.created',
      data: { first_name: 'Max', email: 'max@example.com', tariff: 'basic', password: 'hunter2' },
    };
    const result = anonymizer.anonymizeUnknown(event) as any;
    expect(result.event_type).toBe('contact.created');
    expect(result.data.first_name).toMatch(/^person_/);
    expect(result.data.email).toMatch(/@anonymized\.invalid$/);
    expect(result.data.tariff).toBe('basic');
    expect(result.data.password).toBe('[REDACTED]');
  });

  it('strict mode redacts unrecognized string leaves but keeps identifiers', () => {
    const record = {
      request_id: 'req-1',
      user_id: 'u1',
      status: 'ok',
      note: 'customer prefers evening calls',
    };
    const result = anonymizer.anonymizeUnknown(record, { strict: true }) as any;
    expect(result.request_id).toBe('req-1');
    expect(result.user_id).toBe('u1');
    expect(result.status).toBe('ok');
    expect(result.note).toBe('[REDACTED]');
  });
});

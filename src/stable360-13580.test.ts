import { describe, expect, it } from 'vitest';

import { createAnonymizer } from './index';
import type { Schema, SchemaResolver } from './types';

// STABLE360-13580: PII that passed through anonymized responses (activity feed, thread
// timeline, message/thread titles, cc names, file names)
const anonymizer = createAnonymizer({ orgId: '123', secret: 'test-secret' });

const schemas: Record<string, Schema> = {
  opportunity: {
    slug: 'opportunity',
    attributes: [
      { name: 'delivery_address', type: 'relation_address' },
      { name: 'status', type: 'select' },
    ],
  },
  message: { slug: 'message', attributes: [{ name: 'subject', type: 'string' }] },
  file: { slug: 'file', attributes: [{ name: 'filename', type: 'string' }] },
};
const schemaResolver: SchemaResolver = async ({ slug }) => schemas[slug] ?? null;

const USER_EMAIL = 'jane.user@epilot.cloud';
const caller = {
  EpilotAuth: {
    token: 'eyJ.payload.sig',
    userId: '10006129',
    email: USER_EMAIL,
    claims: { sub: 's-1', email: USER_EMAIL, 'cognito:username': USER_EMAIL, 'custom:ivy_user_id': '10006129' },
  },
};

const leaks = (value: unknown, ...needles: string[]) => {
  const json = JSON.stringify(value);

  return needles.filter((needle) => json.includes(needle));
};

describe('STABLE360-13580', () => {
  it('masks the nested caller security context of activities', async () => {
    const result = await anonymizer.anonymizeResponse(
      { results: [{ _id: 'a1', type: 'EntityUpdated', title: 'Updated', message: '{{caller}} updated', caller, payload: {} }] },
      { schemaResolver },
    );

    const masked = result.results[0].caller.EpilotAuth;
    expect(leaks(result, USER_EMAIL, 'eyJ.payload.sig')).toEqual([]);
    expect(masked.email).toMatch(/@anonymized\.invalid$/);
    expect(masked.claims['cognito:username']).toBe(masked.email);
    expect(masked.token).toBe('[REDACTED]');
    // ids stay joinable
    expect(masked.userId).toBe('10006129');
    expect(masked.claims['custom:ivy_user_id']).toBe('10006129');
  });

  it('masks relation_address values and non-schema journey data in activity entity snapshots', async () => {
    const result = await anonymizer.anonymizeResponse(
      {
        results: [
          {
            _id: 'a1',
            type: 'EntityUpdated',
            title: 'Updated',
            message: 'updated',
            caller,
            payload: {
              entity: {
                _id: 'o1',
                _org: '123',
                _schema: 'opportunity',
                status: 'open',
                journey_data: { first_name: 'Max', last_name: 'Mustermann', street: 'Hauptstr. 1', city: 'Köln', zip: '50667' },
                delivery_address: [
                  {
                    _id: 'addr-1',
                    $relation_ref: { entity_id: 'c1', path: 'address' },
                    street: 'Hauptstr.',
                    street_number: '1',
                    city: 'Köln',
                    postal_code: '50667',
                  },
                ],
              },
            },
          },
        ],
      },
      { schemaResolver },
    );

    const entity = result.results[0].payload.entity;
    expect(leaks(entity, 'Max', 'Mustermann', 'Hauptstr')).toEqual([]);
    expect(entity.status).toBe('open');
    expect(entity.delivery_address[0].$relation_ref).toEqual({ entity_id: 'c1', path: 'address' });
    expect(entity.delivery_address[0].street).toMatch(/^street_/);
    expect(entity.delivery_address[0].street_number).toBeUndefined();
    // quasi-identifiers are kept by policy (ADDRESS_KEEP_KEYS)
    expect(entity.delivery_address[0].postal_code).toBe('50667');
  });

  it('scrubs payloads of activities stored without a caller (thread timeline)', async () => {
    const result = await anonymizer.anonymizeResponse({
      results: [
        {
          _id: 'a2',
          type: 'ThreadMarkedAsDone',
          title: 'Thread marked as Done',
          message: '{{caller payload.caller}} marked the Thread as Done',
          timestamp: '2026-10-30T10:00:00Z',
          payload: { orgId: '123', threadId: 't1', caller: { userId: 'u1', email: USER_EMAIL } },
          operations: [],
        },
      ],
    });

    expect(leaks(result, USER_EMAIL)).toEqual([]);
    expect(result.results[0].payload.caller.userId).toBe('u1');
  });

  it('scrubs identifiers in JSON outside any recognized shape', async () => {
    const result = await anonymizer.anonymizeResponse({ data: { note: `contact ${USER_EMAIL}` } });

    expect(result.data.note).toMatch(/^contact [0-9a-f]{8}@anonymized\.invalid$/);
  });

  it('masks message titles and cc/bcc names, also inside thread.latest_message', async () => {
    const message = {
      _id: 'm1',
      _org: '123',
      _schema: 'message',
      _title: 'Rechnung für Max Mustermann',
      subject: 'Rechnung für Max Mustermann',
      from: { name: 'Max Mustermann', address: 'max@example.com' },
      cc: [{ name: 'Erika Musterfrau', address: 'erika@example.com' }],
      bcc: [{ name: 'Hans Meier', address: 'hans@example.com' }],
    };
    const thread = { _id: 't1', _org: '123', _schema: 'thread', _title: 'Rechnung für Max Mustermann', latest_message: message };

    const result = await anonymizer.anonymizeResponse({ results: [message, thread] }, { schemaResolver });

    expect(leaks(result, 'Mustermann', 'Musterfrau', 'Meier', '@example.com')).toEqual([]);
    expect(result.results[0]._title).toBe('[REDACTED]');
    expect(result.results[0].cc[0].name).toMatch(/^person_/);
    expect(result.results[1]._title).toBe('[REDACTED]');
    expect(result.results[1].latest_message._title).toBe('[REDACTED]');
  });

  it('masks file names consistently with the file title', async () => {
    const file = {
      _id: 'f1',
      _org: '123',
      _schema: 'file',
      _title: 'Rechnung_Mustermann.pdf',
      filename: 'Rechnung_Mustermann.pdf',
      mime_type: 'application/pdf',
    };

    const result = await anonymizer.anonymizeResponse({ results: [file] }, { schemaResolver });

    expect(result.results[0].filename).toMatch(/^value_[0-9a-f]{8}$/);
    expect(result.results[0]._title).toBe(result.results[0].filename);
    expect(result.results[0].mime_type).toBe('application/pdf');
  });
});

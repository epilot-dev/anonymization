import { describe, expect, it } from 'vitest';

import { createAnonymizer, getAttributeStrategy } from './index';
import type { Schema } from './types';
import { isValidIban } from './value-detection';

const anonymizer = createAnonymizer({ orgId: '16581838', secret: 'test-secret' });

const MAPS_LINK =
  'https://www.google.de/maps/place/Schiltacher+Str.+33,+70569+Stuttgart/@48.7413596,9.1362755,725m/data=!3m2!1e3!4b1!4m6!3m5!1s0x4799dc937d6a341f:0x6f4012ba497d9f53!8m2!3d48.7413596!4d9.1388504!16s%2Fg%2F11c1jq8f84';

const opportunitySchema: Schema = {
  slug: 'opportunity',
  attributes: [
    { name: 'link_gebaeudeansicht', type: 'string', label: 'Link Gebäudeansicht' },
    { name: 'public_link', type: 'string', data_classification: 'public' },
  ],
};

const expectNoAddress = (value: string) => {
  for (const leaked of ['Schiltacher', 'Str.+33', '48.7413596', '9.1362755', '9.1388504', '0x4799dc937d6a341f', '11c1jq8f84']) {
    expect(value).not.toContain(leaked);
  }
};

describe('map links (STABLE360-13580: link_gebaeudeansicht)', () => {
  it('masks the place and rounds the position of a Google Maps link in an unclassified attribute', async () => {
    const body = {
      _id: '73557d72',
      _org: '16581838',
      _schema: 'opportunity',
      link_gebaeudeansicht: MAPS_LINK,
    };
    const result = await anonymizer.anonymizeResponse(body, { schemaResolver: async () => opportunitySchema });

    expectNoAddress(result.link_gebaeudeansicht);
    expect(result.link_gebaeudeansicht).toMatch(
      /^https:\/\/www\.google\.de\/maps\/place\/street_[0-9a-f]{8},\+70569\+Stuttgart\/@48\.74,9\.14,725m$/,
    );
  });

  it('masks the link inside activity feed payloads and operations', async () => {
    const body = {
      results: [
        {
          type: 'EntityUpdated',
          payload: { entity: { _id: 'o1', _org: '16581838', _schema: 'opportunity', link_gebaeudeansicht: MAPS_LINK } },
          operations: [{ operation: 'updateEntity', payload: { link_gebaeudeansicht: MAPS_LINK } }],
        },
      ],
    };
    const result = (await anonymizer.anonymizeResponse(body, { schemaResolver: async () => opportunitySchema })) as any;

    expectNoAddress(JSON.stringify(result));
  });

  it('keeps an attribute classified public untouched', async () => {
    const body = { _id: 'o1', _org: '16581838', _schema: 'opportunity', public_link: MAPS_LINK };
    const result = await anonymizer.anonymizeResponse(body, { schemaResolver: async () => opportunitySchema });

    expect(result.public_link).toBe(MAPS_LINK);
  });

  it('is deterministic and idempotent', () => {
    const once = anonymizer.scrub(MAPS_LINK) as string;

    expect(anonymizer.scrub(MAPS_LINK)).toBe(once);
    expect(anonymizer.scrub(once)).toBe(once);
  });

  it.each([
    ['google query', 'https://maps.google.com/?q=Hauptstra%C3%9Fe+5,+10115+Berlin', ['Hauptstr', 'Hauptstraße']],
    ['google coordinates query', 'https://www.google.com/maps/search/?api=1&query=48.7413596,9.1362755', ['7413596']],
    ['google place id', 'https://www.google.com/maps/place/?q=place_id:ChIJ123&cid=1234567890', ['ChIJ123', '1234567890']],
    ['apple', 'https://maps.apple.com/?address=Berliner+Stra%C3%9Fe+12,+10115+Berlin&ll=52.5200066,13.404954', ['Berliner', '5200066']],
    ['bing', 'https://www.bing.com/maps?where1=Am+Ring+3+50667+K%C3%B6ln&cp=50.9375123~6.9602786', ['Ring', '9375123']],
    ['openstreetmap', 'https://www.openstreetmap.org/?mlat=48.7413596&mlon=9.1362755#map=19/48.7413596/9.1362755', ['7413596', '1362755']],
    ['short link', 'https://maps.app.goo.gl/AbCdEf123456', ['AbCdEf123456']],
  ])('anonymizes %s links', (_, link, leaks) => {
    const result = anonymizer.scrub(`Gebäude: ${link}`) as string;

    expect(result.startsWith('Gebäude: https://')).toBe(true);
    for (const leaked of leaks) {
      expect(result).not.toContain(leaked);
    }
    expect(anonymizer.scrub(result)).toBe(result);
  });

  it('keeps postal code and city of a map query', () => {
    const result = anonymizer.scrub('https://maps.google.com/?q=Hauptstra%C3%9Fe+5,+10115+Berlin') as string;

    expect(new URL(result).searchParams.get('q')).toMatch(/^street_[0-9a-f]{8}, 10115 Berlin$/);
  });
});

describe('PII embedded in other URLs', () => {
  it('scrubs URL-encoded emails, phones in query values and streets in paths', () => {
    const url = 'https://portal.example.com/u/max.mustermann%40example.com/haus/Hauptstra%C3%9Fe%205?tel=%2B49%20170%201234567&tab=1';
    const result = anonymizer.scrub(url) as string;

    for (const leaked of ['mustermann', 'Hauptstra', '1234567']) {
      expect(result).not.toContain(leaked);
    }
    expect(result).toContain('anonymized.invalid');
    expect(result).toContain('tab=1');
    expect(anonymizer.scrub(result)).toBe(result);
  });

  it('removes credentials from URL userinfo', () => {
    const result = anonymizer.scrub('https://max:geheim@files.example.com/a.pdf') as string;

    expect(result).not.toContain('max');
    expect(result).not.toContain('geheim');
  });
});

describe('German street addresses in free text', () => {
  it.each([
    'Hauptstraße 5',
    'Hauptstrasse 5',
    'Hauptstr. 5',
    'Schiltacher Str. 33',
    'Berliner Straße 12a',
    'Max-Planck-Str. 12-14',
    'Am Ring 3',
    'Lindenallee 7',
    'Kirchgasse 2 b',
    'Mühlenweg 10/1',
    'Kurfürstendamm 21',
  ])('replaces "%s" and keeps postal code + city', (street) => {
    const result = anonymizer.scrub(`Vor-Ort-Termin: ${street}, 70569 Stuttgart.`) as string;

    expect(result).toMatch(/^Vor-Ort-Termin: street_[0-9a-f]{8}, 70569 Stuttgart\.$/);
    expect(anonymizer.scrub(result)).toBe(result);
  });
});

describe('IBAN checksum', () => {
  it('validates the mod-97 checksum', () => {
    expect(isValidIban('DE89370400440532013000')).toBe(true);
    expect(isValidIban('AT611904300234573201')).toBe(true);
    expect(isValidIban('DE89370400440532013001')).toBe(false);
  });

  it('masks a valid IBAN followed by uppercase text, but not IBAN-shaped codes', () => {
    const result = anonymizer.scrub('DE89 3704 0044 0532 0130 00 BIC COBADEFFXXX') as string;

    expect(result).toMatch(/^iban_[0-9a-f]{8} BIC COBADEFFXXX$/);
    expect(anonymizer.scrub('Code DE12ABCDEFGHIJKLMN')).toBe('Code DE12ABCDEFGHIJKLMN');
  });
});

describe('false positives stay unchanged', () => {
  it.each([
    'A-WP_PV-129-2504252_2505234_V2',
    'OV60WPE004009',
    '1-0:1.8.0',
    '2026-10-24',
    '2026-10-24T05:30:00.000Z',
    '1.299,00 €',
    '19,99 EUR',
    '73557d72-ff64-46ef-886d-93d221e45ea4',
    'Wärmepumpe Wärmebedarf',
    'Spring 2026',
    'Abnahme PV: 03.03.26 14 Uhr',
    'https://www.epilot.cloud/de/blog/energy-xrm-2026',
    'https://portal.example.com/030-1234567',
    'https://docs.example.com/v1/entities/73557d72-ff64-46ef-886d-93d221e45ea4?size=100#section-2',
    'https://www.google.de/search?q=w%C3%A4rmepumpe',
    'Einzelversorgungsgebiet',
    'Möhringen',
  ])('%s', (value) => {
    expect(anonymizer.scrub(value)).toBe(value);
  });
});

describe('classification fixes', () => {
  it('maps internal_user attributes to the user strategy', () => {
    expect(getAttributeStrategy({ slug: 'email_template', attributeName: 'created_by', attribute: { name: 'created_by', type: 'internal_user' } })).toBe('user');
  });

  it.each(['billing_account', 'calendar_event', 'contract', 'lead', 'request', 'ticket'])('masks %s _title', (slug) => {
    expect(getAttributeStrategy({ slug, attributeName: '_title' })).toBe('text');
  });

  it('lets pii honor curated strategies (names stay person pseudonyms)', () => {
    const pii = (name: string, type = 'string') =>
      getAttributeStrategy({ slug: 'contact', attributeName: name, attribute: { name, type, data_classification: 'pii' } });

    expect(pii('first_name')).toBe('person');
    expect(pii('salutation')).toBe('redact');
    expect(pii('email', 'email')).toBe('email');
    expect(pii('customer_number')).toBe('value');
  });

  it('never keeps a pii attribute, even with a keep override', () => {
    expect(
      getAttributeStrategy({
        slug: 'contact',
        attributeName: 'notes',
        attribute: { name: 'notes', type: 'string', multiline: true, data_classification: 'pii' },
        overrides: { 'contact:notes': 'keep' },
      }),
    ).toBe('redact');
  });
});

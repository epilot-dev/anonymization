/**
 * Value-level PII detection for strings no field name or type classified.
 *
 * Used by the catch-all scrub (`scrubText`): only the matched span is replaced, the rest of the
 * value stays intact. Covers what field-name rules cannot see, e.g. a custom
 * `link_gebaeudeansicht` attribute holding a Google Maps link to the customer's house.
 */

import { hasIbanCountryLength } from './iban-countries';

/** Replacers for detected spans (the pseudonymizer's own, or the redactor without a secret) */
export type ValueReplacers = {
  street: (value: string) => string;
  value: (value: string) => string;
};

/**
 * Text scrubber for URL components (emails / IBANs / phones / streets). `path` skips phone
 * numbers: digit-and-dash path segments are ids and slugs far more often ("/030-1234567").
 */
type PlainScrub = (value: string, context?: 'path') => string;

// --- German street addresses -------------------------------------------------------------

const SUFFIX_LOWER = '(?:stra(?:ß|ss)e|str\\.|weg|platz|allee|gasse|ring|damm)';
const SUFFIX_CAP = '(?:Stra(?:ß|ss)e|Str\\.|Weg|Platz|Allee|Gasse|Ring|Damm)';

/**
 * A street name followed by a house number: "Hauptstraße 5", "Schiltacher Str. 33",
 * "Max-Planck-Str. 12a", "Am Ring 3", "Lindenallee 12-14".
 *
 * - the street word is capitalized (German nouns): a compound ending in a lowercase suffix
 *   ("Hauptstraße", "Mühlenweg") or a standalone capitalized suffix after up to two
 *   capitalized words ("Berliner Straße", "Am Alten Weg")
 * - house numbers have 1-3 digits, so years ("Spring 2026") do not match
 * - postal code and city are NOT part of the match: they stay visible, like on address items
 */
export const STREET_PATTERN = new RegExp(
  `(?<![\\p{L}\\p{N}_])` +
    `(?:\\p{Lu}[\\p{L}'.-]*\\s+){0,2}` +
    `(?:\\p{Lu}[\\p{L}-]*?(?:${SUFFIX_LOWER}|-${SUFFIX_CAP})|${SUFFIX_CAP})` +
    `\\s*\\d{1,3}(?:\\s?[a-zA-Z](?!\\p{L}))?(?:\\s?[-/]\\s?\\d{1,3}[a-zA-Z]?)?` +
    `(?![\\p{L}\\p{N}]|[.,:]\\d)`,
  'gu',
);

/** Necessary condition for STREET_PATTERN: a street suffix followed by a house number */
export const STREET_CANDIDATE = /(?:stra(?:ß|ss)e|str\.|weg|platz|allee|gasse|ring|damm)\s*\d/i;

/** "70569 Stuttgart": kept next to a pseudonymized place, like on address items */
const ZIP_CITY_PATTERN = /\b\d{5}\s+\p{Lu}[\p{L}-]+(?:\s\p{Lu}[\p{L}-]+)?/u;

export const scrubStreets = (value: string, replacers: ValueReplacers): string =>
  STREET_CANDIDATE.test(value) ? value.replace(STREET_PATTERN, (match) => replacers.street(match)) : value;

// --- IBAN checksum -----------------------------------------------------------------------

/** ISO 13616 check of a compact IBAN: known country code, that country's length, mod-97 checksum */
export const isValidIban = (compact: string): boolean => {
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact) || !hasIbanCountryLength(compact)) {
    return false;
  }

  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const digits = char >= 'A' ? String(char.charCodeAt(0) - 55) : char;
    for (const digit of digits) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }

  return remainder === 1;
};

/**
 * Pseudonymize an IBAN_PATTERN match only when it is a valid IBAN. The pattern is greedy over
 * space-separated groups ("DE89 3704 … 00 BIC"), so shorter prefixes ending at a space are
 * tried too; the unmatched tail is kept.
 */
export const replaceIban = (match: string, iban: (value: string) => string): string => {
  const ends = [match.length];
  for (let i = match.length - 1; i > 0; i--) {
    if (match[i] === ' ') {
      ends.push(i);
    }
  }

  for (const end of ends) {
    const candidate = match.slice(0, end).trimEnd();
    if (isValidIban(candidate.replace(/ /g, ''))) {
      return iban(candidate) + match.slice(candidate.length);
    }
  }

  return match;
};

// --- URLs ---------------------------------------------------------------------------------

/** URLs embedded in a string value */
export const URL_TOKEN = /\bhttps?:\/\/[^\s<>"'`]+/g;

const PSEUDONYM_PATTERN = /^(?:street|value)_[0-9a-f]{8}\b|^\[REDACTED\]/;

/** lat/lng with more precision than 2 decimals (~1 km) */
const PRECISE_COORDINATE = /-?\d{1,3}\.\d{3,}/g;
const COORDINATE_PAIR = /^\s*-?\d{1,3}(?:\.\d+)?\s*[,~ ]\s*-?\d{1,3}(?:\.\d+)?\s*$/;

const roundCoordinates = (value: string): string =>
  value.replace(PRECISE_COORDINATE, (number) => (Math.round(Number(number) * 100) / 100).toFixed(2));

const safeDecode = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

/** Map-link location text (place name / address / search query) -> pseudonym, keeping zip + city */
const anonymizePlace = (text: string, replacers: ValueReplacers): string => {
  if (!text.trim() || PSEUDONYM_PATTERN.test(text.trim())) {
    return text;
  }
  if (COORDINATE_PAIR.test(text)) {
    return roundCoordinates(text);
  }

  const zipCity = text.match(ZIP_CITY_PATTERN)?.[0];

  return zipCity ? `${replacers.street(text)}, ${zipCity}` : replacers.street(text);
};

type MapProvider = 'google' | 'apple' | 'bing' | 'osm' | 'shortlink';

const getMapProvider = (url: URL): MapProvider | undefined => {
  const host = url.hostname.toLowerCase();
  const path = url.pathname.toLowerCase();

  if (host === 'maps.app.goo.gl' || (host === 'goo.gl' && path.startsWith('/maps'))) {
    return 'shortlink';
  }
  if (/^maps\.google\./.test(host) || (/(^|\.)google\.[a-z]{2,3}(\.[a-z]{2})?$/.test(host) && path.startsWith('/maps'))) {
    return 'google';
  }
  if (host === 'maps.apple.com') {
    return 'apple';
  }
  if (/(^|\.)bing\.com$/.test(host) && path.startsWith('/maps')) {
    return 'bing';
  }
  if (/(^|\.)(openstreetmap\.org|osm\.org)$/.test(host)) {
    return 'osm';
  }

  return undefined;
};

/** Google Maps path segments that are routing keywords, not locations */
const GOOGLE_PATH_KEYWORDS = new Set(['maps', 'place', 'search', 'dir', 'embed', 'v1', 'preview', 'contrib', '']);

/** Query params of map links carrying a location (address text or coordinates) */
const MAP_LOCATION_PARAMS = new Set([
  'q',
  'query',
  'address',
  'daddr',
  'saddr',
  'destination',
  'origin',
  'll',
  'sll',
  'center',
  'near',
  'name',
  'where1',
  'cp',
  'sp',
  'rtp',
  'mlat',
  'mlon',
  'lat',
  'lon',
  'lng',
  'route',
]);

/** Query params of map links identifying a concrete place (resolve to the address) */
const MAP_PLACE_ID_PARAMS = new Set(['cid', 'ftid', 'place_id', 'query_place_id', 'auid', 'place-id', 'ss']);

const encodeGoogleSegment = (value: string) => encodeURIComponent(value).replace(/%20/g, '+').replace(/%2C/gi, ',');

const anonymizeMapUrl = (url: URL, provider: MapProvider, replacers: ValueReplacers): string => {
  if (provider === 'shortlink') {
    // the short id resolves to the shared place
    const id = url.pathname.split('/').filter(Boolean).pop();
    if (id && !PSEUDONYM_PATTERN.test(id)) {
      url.pathname = url.pathname.replace(id, replacers.value(id));
    }

    return url.toString();
  }

  if (provider === 'google') {
    url.pathname = url.pathname
      .split('/')
      // `data=` holds place feature / knowledge-graph ids and precise coordinates
      .filter((segment) => !segment.startsWith('data='))
      .map((segment) => {
        if (GOOGLE_PATH_KEYWORDS.has(segment.toLowerCase())) {
          return segment;
        }
        if (segment.startsWith('@')) {
          return roundCoordinates(segment);
        }

        return encodeGoogleSegment(anonymizePlace(safeDecode(segment.replace(/\+/g, ' ')), replacers));
      })
      .join('/');
  }

  for (const [key, val] of [...url.searchParams.entries()]) {
    const lowerKey = key.toLowerCase();
    if (MAP_PLACE_ID_PARAMS.has(lowerKey)) {
      url.searchParams.set(key, PSEUDONYM_PATTERN.test(val) ? val : replacers.value(val));
    } else if (lowerKey === 'mlat' || lowerKey === 'mlon' || lowerKey === 'lat' || lowerKey === 'lon' || lowerKey === 'lng') {
      url.searchParams.set(key, roundCoordinates(val));
    } else if (MAP_LOCATION_PARAMS.has(lowerKey)) {
      url.searchParams.set(key, anonymizePlace(val, replacers));
    }
  }

  // OpenStreetMap: "#map=19/48.7413596/9.1362755"
  if (url.hash) {
    url.hash = roundCoordinates(url.hash);
  }

  return url.toString();
};

/** Scrub a generic URL's components; returns the input unchanged when nothing was found */
const anonymizeGenericUrl = (raw: string, url: URL, scrub: PlainScrub, replacers: ValueReplacers): string => {
  let changed = false;

  if (url.username || url.password) {
    url.username = url.username ? replacers.value(safeDecode(url.username)) : '';
    url.password = '';
    changed = true;
  }

  const segments = url.pathname.split('/').map((segment) => {
    const decoded = safeDecode(segment);
    const scrubbed = scrub(decoded, 'path');
    if (scrubbed === decoded) {
      return segment;
    }
    changed = true;

    return encodeURIComponent(scrubbed);
  });

  for (const [key, val] of [...url.searchParams.entries()]) {
    const scrubbed = scrub(val);
    if (scrubbed !== val) {
      url.searchParams.set(key, scrubbed);
      changed = true;
    }
  }

  let hash = url.hash;
  if (hash) {
    const decoded = safeDecode(hash);
    const scrubbed = scrub(decoded);
    if (scrubbed !== decoded) {
      hash = scrubbed;
      changed = true;
    }
  }

  if (!changed) {
    return raw;
  }

  url.pathname = segments.join('/');
  url.hash = hash;

  return url.toString();
};

/** Anonymize one URL: map links lose place + precise position, other URLs their embedded PII */
export const anonymizeUrl = (raw: string, scrub: PlainScrub, replacers: ValueReplacers): string => {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return scrub(raw);
  }

  const provider = getMapProvider(url);
  if (provider) {
    const anonymized = anonymizeMapUrl(url, provider, replacers);
    // keep an already-anonymized link byte-identical (idempotency)
    return anonymized === new URL(raw).toString() ? raw : anonymized;
  }

  return anonymizeGenericUrl(raw, url, scrub, replacers);
};

/** Apply `scrub` to the non-URL parts of a string and `anonymizeUrl` to each embedded URL */
export const scrubWithUrls = (value: string, scrub: PlainScrub, replacers: ValueReplacers): string => {
  if (!value.includes('://')) {
    return scrub(value);
  }

  let result = '';
  let last = 0;
  for (const match of value.matchAll(URL_TOKEN)) {
    const index = match.index ?? 0;
    result += scrub(value.slice(last, index)) + anonymizeUrl(match[0], scrub, replacers);
    last = index + match[0].length;
  }

  return result + scrub(value.slice(last));
};

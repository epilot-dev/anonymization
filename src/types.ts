/**
 * Structural types for epilot entity schemas.
 *
 * These are intentionally minimal and structural: any object satisfying this shape works,
 * including schemas from `@epilot/entity-client`, raw Entity API responses, or static fixtures.
 * The package has no dependency on epilot-internal packages.
 */

/** How a single attribute value is anonymized */
export type AnonymizationStrategy =
  | 'keep'
  /** replace with the static redaction placeholder */
  | 'redact'
  /** deterministic person pseudonym, e.g. `person_4f2a9b1c` */
  | 'person'
  /** deterministic company pseudonym, e.g. `company_4f2a9b1c` */
  | 'company'
  /** deterministic email-shaped pseudonym, e.g. `4f2a9b1c@anonymized.invalid` */
  | 'email'
  /** deterministic phone-shaped pseudonym, e.g. `+0083920174` */
  | 'phone'
  /** deterministic IBAN pseudonym, e.g. `iban_4f2a9b1c` */
  | 'iban'
  /** deterministic generic value pseudonym (keeps identifiers joinable), e.g. `value_4f2a9b1c` */
  | 'value'
  /** deterministic text pseudonym (keeps list items distinguishable), e.g. `title_4f2a9b1c` */
  | 'text'
  /** generalize a date to year precision, e.g. `1985-06-14` -> `1985-01-01` */
  | 'date_year'
  /** generalize an address: keep postal_code/city/country, pseudonymize street, drop the rest */
  | 'address'
  /** scrub payment details: pseudonymize IBAN/holder identifiers, keep bank metadata */
  | 'payment';

/** Data classification set on a schema attribute (`data_classification` in the Entity API) */
export type DataClassification = 'public' | 'pii';

/** Minimal structural shape of an entity schema attribute */
export type Attribute = {
  name: string;
  type?: string;
  multiline?: boolean;
  data_classification?: DataClassification;
  // any other attribute properties are accepted and ignored
  [key: string]: unknown;
};

/** Minimal structural shape of an entity schema */
export type Schema = {
  slug?: string;
  attributes?: Attribute[];
  [key: string]: unknown;
};

/** An epilot entity (or partial entity, e.g. an activity diff) */
export type EntityLike = Record<string, unknown>;

/**
 * Resolves the schema for a given (orgId, slug). Injected by the consumer:
 * - entity-api uses its DynamoDB-backed schema store
 * - other services can use `@epilot/entity-client` `getSchema`
 * - offline/sandboxed contexts can serve a static map
 *
 * Returning `null` is safe: classification falls back to curated defaults by field name.
 */
export type SchemaResolver = (params: { orgId: string; slug: string }) => Promise<Schema | null> | Schema | null;

/** Optional logger hooks — the package itself never logs, phones home, or persists anything */
export type AnonymizerLogger = {
  warn?: (message: string, context?: Record<string, unknown>) => void;
};

export type AnonymizerOptions = {
  /** Organization id: pseudonyms are stable within an org and differ across orgs */
  orgId: string;
  /**
   * HMAC secret used to derive pseudonyms. Treat like any credential (inject from a secret
   * store, never commit). When omitted, the anonymizer FAILS SAFE: every value classified as
   * PII is replaced with the static redaction placeholder instead of a pseudonym.
   */
  secret?: string;
  /**
   * Extend or override the curated classification defaults.
   * Keys are `${schemaSlug}:${attributeName}`; `*` matches any schema.
   * Example: `{ 'mycustom:internal_note': 'redact', 'order:_title': 'text' }`
   */
  overrides?: Record<string, AnonymizationStrategy>;
  logger?: AnonymizerLogger;
};

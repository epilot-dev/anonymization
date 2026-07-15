import type { AnonymizationStrategy } from './types';

/**
 * Curated classification defaults.
 *
 * These are versioned, reviewable data — changes ship as minor releases so consumers can
 * audit exactly what is (and is not) masked. Organizations extend/override per attribute via
 * `data_classification` on the entity schema or the `overrides` option.
 */

/** Placeholder for redacted values */
export const REDACTED_PLACEHOLDER = '[REDACTED]';

/** Domain used for email-shaped pseudonyms. `.invalid` is reserved (RFC 2606): never routable. */
export const PSEUDONYM_EMAIL_DOMAIN = 'anonymized.invalid';

/**
 * Default strategies by attribute type (apply when no data_classification is set).
 * Types not listed default to 'keep'.
 */
export const STRATEGY_BY_ATTRIBUTE_TYPE: Record<string, AnonymizationStrategy> = {
  email: 'email',
  phone: 'phone',
  address: 'address',
  payment: 'payment',
};

/**
 * Curated built-in PII fields, keyed by `${schema}:${attribute}`.
 * The `*` schema wildcard matches the attribute name on any schema.
 *
 * These are well-known identifier / free-text fields that commonly contain personal data.
 * `data_classification: 'public'` on the schema attribute opts a field out.
 */
export const DEFAULT_PII_FIELDS: Record<string, AnonymizationStrategy> = {
  // person names & birthdates on any schema
  '*:first_name': 'person',
  '*:last_name': 'person',
  '*:middle_name': 'person',
  '*:full_name': 'person',
  '*:salutation': 'redact',
  '*:birthdate': 'date_year',
  '*:date_of_birth': 'date_year',
  // common identifier field names on any schema (also covers plain string-typed variants)
  '*:email': 'email',
  '*:phone': 'phone',
  '*:iban': 'iban',
  // contacts & accounts
  'contact:_title': 'person',
  'account:_title': 'company',
  'account:name': 'company',
  'account:company_name': 'company',
  'account:registration_number': 'value',
  'account:tax_id': 'value',
  // known free-text fields likely to contain PII
  'opportunity:_title': 'text',
  'opportunity:description': 'redact',
  'note:content': 'redact',
  'comment:content': 'redact',
  'message:subject': 'redact',
  'message:text': 'redact',
  'message:html': 'redact',
  'thread:topic': 'redact',
};

/**
 * Additional field-name heuristics used ONLY by the non-schema-aware mode
 * (`anonymizeUnknown`) for arbitrary JSON such as audit logs or inbound integration events.
 */
export const UNKNOWN_FIELD_HEURISTICS: Record<string, AnonymizationStrategy> = {
  name: 'person',
  firstname: 'person',
  lastname: 'person',
  display_name: 'person',
  email_address: 'email',
  phone_number: 'phone',
  mobile: 'phone',
  telephone: 'phone',
  street: 'address',
  street_number: 'redact',
  account_holder: 'person',
  account_owner: 'person',
  account_number: 'value',
  credit_card: 'value',
  password: 'redact',
  secret: 'redact',
  token: 'redact',
  authorization: 'redact',
};

/** Keys always preserved on address items (quasi-identifiers useful for analysis) */
export const ADDRESS_KEEP_KEYS = ['_id', '_tags', 'postal_code', 'zip', 'city', 'country', 'countrycode'];

/** Keys on payment items whose values identify a person/account and must be pseudonymized */
export const PAYMENT_PSEUDONYMIZE_KEY_PATTERN = /iban|account|holder|owner|card|number/i;

/** Keys never anonymized on any object (system metadata, not PII) */
export const SYSTEM_KEEP_KEYS = [
  '_id',
  '_org',
  '_schema',
  '_created_at',
  '_updated_at',
  '_tags',
  '_acl',
  '_owners',
  '_purpose',
  '_manifest',
  '$relation',
  '$relation_ref',
];

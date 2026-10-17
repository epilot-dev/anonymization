import type { AnonymizationStrategy } from '@epilot/anonymization';

/**
 * Fullstory MCP preset.
 *
 * Upstream: https://developer.fullstory.com/mcp/introduction/
 * Auth: `Authorization: Bearer <API key>` (the documented option for gateways).
 */
export const FULLSTORY_UPSTREAM_URL = {
  eu1: 'https://api.eu1.fullstory.com/mcp/fullstory',
  na1: 'https://api.na1.fullstory.com/mcp/fullstory',
} as const;

/** Region is encoded in the API key prefix (`eu1.` / `na1.`) */
export const fullstoryUpstreamFromApiKey = (apiKey: string): string =>
  apiKey.startsWith('na1.') ? FULLSTORY_UPSTREAM_URL.na1 : FULLSTORY_UPSTREAM_URL.eu1;

/**
 * Fullstory identity / user-var field names (lowercased, `*:` = any object).
 * Covers FS.identify / setUserVars built-ins and their export-API spellings.
 */
export const FULLSTORY_OVERRIDES: Record<string, AnonymizationStrategy> = {
  '*:displayname': 'person',
  '*:user_displayname': 'person',
  '*:userdisplayname': 'person',
  '*:user_name': 'person',
  '*:username': 'person',
  '*:useremail': 'email',
  '*:user_email': 'email',
  '*:email_str': 'email',
  '*:name_str': 'person',
  '*:displayname_str': 'person',
  // uid = the customer's own user id -> pseudonymize but keep joinable
  '*:uid': 'value',
  '*:user_uid': 'value',
  '*:useruid': 'value',
  '*:user_id_str': 'value',
  // network / geo quasi-identifiers
  '*:ip': 'redact',
  '*:ip_address': 'redact',
  '*:ipaddress': 'redact',
  '*:client_ip': 'redact',
  '*:latlong': 'redact',
  '*:lat': 'redact',
  '*:lng': 'redact',
  '*:latitude': 'redact',
  '*:longitude': 'redact',
};

/**
 * Keys whose whole subtree is a bag of customer-defined user properties. Everything below is
 * treated STRICTLY: known PII keys get pseudonymized, all other string leaves are redacted,
 * unless allow-listed via `KEEP_USER_PROPERTIES`. This is the `user_properties` leak.
 */
export const FULLSTORY_USER_PROPERTY_KEYS =
  /^(user_?)?(properties|props|vars|variables|traits)$|^(custom|user|page|session)_?vars$|^identity$/i;

/**
 * Tools whose output cannot be anonymized as text:
 * - `session_screenshot` returns rendered pixels (typed names/emails are only hidden if
 *   Fullstory masking rules already cover them)
 * - `session_get_a11y_tree` / `session_diff` return raw DOM text (form values, names in
 *   headers, table cells) — free text the heuristics cannot reliably classify
 */
export const FULLSTORY_BLOCKED_TOOLS = ['session_screenshot', 'session_get_a11y_tree', 'session_diff'];

/** Links back into the Fullstory app are useful and contain only FS-internal ids */
export const FULLSTORY_KEEP_URL_HOSTS = /(^|\.)fullstory\.com$/i;

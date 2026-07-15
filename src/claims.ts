/**
 * Helper for services enforcing the epilot `anonymize` token claim themselves
 * (e.g. APIs with their own data stores that entity-api enforcement cannot reach).
 *
 * The claim is set by access-token-api (`anonymize: true` on token creation) and
 * internal-auth-api (anonymized service tokens). It is intentionally one-way:
 * a bearer can never use request input to turn anonymization OFF.
 */
export const hasAnonymizeClaim = (claims: Record<string, unknown> | null | undefined): boolean => {
  const value = claims?.anonymize;

  return value === true || value === 'true' || value === '1';
};

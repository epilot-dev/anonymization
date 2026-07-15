import { anonymizeEntity, applyStrategy, getAttributeStrategy } from './entity';
import { createPseudonymizer, type Pseudonymizer } from './pseudonymizer';
import { anonymizeResponse } from './response';
import type { AnonymizationStrategy, AnonymizerOptions, EntityLike, Schema, SchemaResolver } from './types';
import { anonymizeUnknown, scrub } from './unknown';

export * from './claims';
export * from './defaults';
export { anonymizeEntity, applyStrategy, getAttributeStrategy } from './entity';
export { createPseudonymizer, type Pseudonymizer } from './pseudonymizer';
export { anonymizeResponse } from './response';
export * from './types';
export { anonymizeUnknown, scrub } from './unknown';

export type Anonymizer = {
  pseudonymizer: Pseudonymizer;
  /** Schema-aware: anonymize a single entity (or partial entity, e.g. a diff) */
  anonymizeEntity: <T extends EntityLike>(params: { entity: T; schema?: Schema | null; slug?: string }) => T;
  /** Schema-aware: anonymize an arbitrary JSON document containing entities/activities */
  anonymizeResponse: <T>(body: T, opts?: { schemaResolver?: SchemaResolver }) => Promise<T>;
  /** Non-schema-aware: field-name heuristics + pattern scrubbing for arbitrary JSON */
  anonymizeUnknown: (value: unknown, opts?: { strict?: boolean }) => unknown;
  /** Non-schema-aware: pattern-only scrubbing (emails/phones/IBANs) of string leaves */
  scrub: (value: unknown) => unknown;
  /** Resolve the strategy that would be applied to an attribute (for docs/UI/tests) */
  getAttributeStrategy: (params: {
    slug: string;
    attributeName: string;
    attribute?: Schema['attributes'] extends (infer A)[] | undefined ? A : never;
  }) => AnonymizationStrategy;
};

/**
 * Create an anonymizer bound to an organization.
 *
 * SAFETY DEFAULTS:
 * - no secret configured -> static redaction (never raw pass-through)
 * - schema resolution failure -> curated field-name defaults still apply
 * - inputs are never mutated; nothing is logged, persisted, or sent anywhere by this package
 */
export const createAnonymizer = (options: AnonymizerOptions): Anonymizer => {
  const { orgId, secret, overrides, logger } = options;
  const pseudonymizer = createPseudonymizer({ orgId, secret, logger });

  return {
    pseudonymizer,
    anonymizeEntity: (params) => anonymizeEntity({ ...params, pseudonymizer, overrides }),
    anonymizeResponse: (body, opts) =>
      anonymizeResponse({ body, orgId, pseudonymizer, overrides, logger, schemaResolver: opts?.schemaResolver }),
    anonymizeUnknown: (value, opts) => anonymizeUnknown({ value, pseudonymizer, overrides, strict: opts?.strict }),
    scrub: (value) => scrub({ value, pseudonymizer }),
    getAttributeStrategy: (params) => getAttributeStrategy({ ...params, overrides }),
  };
};

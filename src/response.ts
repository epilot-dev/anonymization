import { anonymizeEntity } from './entity';
import type { Pseudonymizer } from './pseudonymizer';
import type { AnonymizationStrategy, AnonymizerLogger, Schema, SchemaResolver } from './types';
import { isPlainObject, mapEntries } from './utils';

type SchemaMap = Map<string, Schema | null>;

type TransformContext = {
  orgId: string;
  schemas: SchemaMap;
  pseudonymizer: Pseudonymizer;
  overrides?: Record<string, AnonymizationStrategy>;
};

/**
 * Schema-aware anonymization of an arbitrary JSON document (API response, event payload, …).
 *
 * Walks the document and anonymizes:
 * - any entity-shaped object (has a string `_schema`) using its org schema
 * - Entity API operation records (activity feed): `payload` and `diff.added/updated/deleted`
 * - Entity API activity records: scrubs emails/phones/IBANs embedded in `title`/`message`/
 *   `payload` free text and pseudonymizes the caller's name/email
 *
 * Schemas are resolved once per (org, slug) via the injected resolver before the synchronous
 * transform pass. A resolver failure is fail-safe: curated field-name defaults still apply.
 */
export const anonymizeResponse = async <T>(params: {
  body: T;
  orgId: string;
  pseudonymizer: Pseudonymizer;
  schemaResolver?: SchemaResolver;
  overrides?: Record<string, AnonymizationStrategy>;
  logger?: AnonymizerLogger;
}): Promise<T> => {
  const { body, orgId, pseudonymizer, schemaResolver, overrides, logger } = params;

  const schemas: SchemaMap = new Map();
  if (schemaResolver) {
    await loadSchemas({ node: body, orgId, schemas, schemaResolver, logger });
  }

  return transformNode(body, { orgId, schemas, pseudonymizer, overrides }) as T;
};

/** Recursively collect and resolve all schemas referenced by entity-shaped nodes */
const loadSchemas = async (params: {
  node: unknown;
  orgId: string;
  schemas: SchemaMap;
  schemaResolver: SchemaResolver;
  logger?: AnonymizerLogger;
}): Promise<void> => {
  const { node, orgId, schemas, schemaResolver, logger } = params;

  if (Array.isArray(node)) {
    for (const item of node) {
      await loadSchemas({ ...params, node: item });
    }

    return;
  }

  if (!isPlainObject(node)) {
    return;
  }

  const slugs: string[] = [];
  if (typeof node._schema === 'string') {
    slugs.push(node._schema);
  }
  // entity operations carry the schema slug in params.slug (diffs have no _schema)
  const paramsSlug = (node.params as Record<string, unknown> | undefined)?.slug;
  if (typeof node.operation === 'string' && typeof paramsSlug === 'string') {
    slugs.push(paramsSlug);
  }

  const entityOrg = typeof node._org === 'string' ? node._org : orgId;
  for (const slug of slugs) {
    const key = `${entityOrg}:${slug}`;
    if (!schemas.has(key)) {
      try {
        schemas.set(key, (await schemaResolver({ orgId: entityOrg, slug })) ?? null);
      } catch (error) {
        // fail safe: without a schema, type-based classification is skipped but
        // curated defaults (by field name) still apply in anonymizeEntity
        logger?.warn?.('@epilot/anonymization: schema resolution failed', { orgId: entityOrg, slug, error });
        schemas.set(key, null);
      }
    }
  }

  for (const value of Object.values(node)) {
    await loadSchemas({ ...params, node: value });
  }
};

const getSchemaFor = (context: TransformContext, slug: string, org?: string): Schema | null =>
  context.schemas.get(`${org ?? context.orgId}:${slug}`) ?? null;

const transformNode = (node: unknown, context: TransformContext): unknown => {
  if (Array.isArray(node)) {
    return node.map((item) => transformNode(item, context));
  }

  if (!isPlainObject(node)) {
    return node;
  }

  if (isEntityLike(node)) {
    const slug = node._schema as string;
    const schema = getSchemaFor(context, slug, node._org as string | undefined);
    const anonymized = anonymizeEntity({
      entity: node,
      schema,
      slug,
      pseudonymizer: context.pseudonymizer,
      overrides: context.overrides,
      nestedSchema: (nestedSlug) => getSchemaFor(context, nestedSlug, node._org as string | undefined),
    });

    // recurse to catch hydrated relations and other nested entities; a submission's
    // entities[] are already anonymized (re-walking them would pseudonymize twice)
    return mapEntries(anonymized, (value, key) =>
      slug === 'submission' && key === 'entities' ? value : transformNode(value, context),
    );
  }

  if (isEntityOperationLike(node)) {
    return transformEntityOperation(node, context);
  }

  if (isActivityLike(node)) {
    return transformActivity(node, context);
  }

  return mapEntries(node, (value) => transformNode(value, context));
};

const transformEntityOperation = (record: Record<string, unknown>, context: TransformContext): unknown => {
  const slug = ((record.params as Record<string, unknown> | undefined)?.slug as string) ?? undefined;
  const payload = record.payload as Record<string, unknown> | undefined;
  const payloadSlug = (payload?._schema as string) ?? slug;

  return mapEntries(record, (value, key) => {
    if (key === 'payload' && isPlainObject(value)) {
      const schema = getSchemaFor(context, payloadSlug, value._org as string | undefined);

      return anonymizeEntity({
        entity: value,
        schema,
        slug: payloadSlug,
        pseudonymizer: context.pseudonymizer,
        overrides: context.overrides,
        nestedSchema: (nestedSlug) => getSchemaFor(context, nestedSlug),
      });
    }
    if (key === 'diff' && isPlainObject(value)) {
      const schema = slug ? getSchemaFor(context, slug) : null;

      return mapEntries(value, (diffPart) =>
        isPlainObject(diffPart)
          ? anonymizeEntity({
              entity: diffPart,
              schema,
              slug: slug ?? '*',
              pseudonymizer: context.pseudonymizer,
              overrides: context.overrides,
              nestedSchema: (nestedSlug) => getSchemaFor(context, nestedSlug),
            })
          : diffPart,
      );
    }

    return transformNode(value, context);
  });
};

const transformActivity = (record: Record<string, unknown>, context: TransformContext): unknown => {
  const { pseudonymizer } = context;

  return mapEntries(record, (value, key) => {
    if ((key === 'title' || key === 'message') && typeof value === 'string') {
      return pseudonymizer.scrubText(value);
    }
    if (key === 'caller' && isPlainObject(value)) {
      return mapEntries(value, (callerValue, callerKey) => {
        if (typeof callerValue !== 'string') {
          return callerValue;
        }
        if (['name', 'display_name', 'full_name'].includes(callerKey)) {
          return pseudonymizer.person(callerValue);
        }
        if (callerKey === 'email') {
          return pseudonymizer.email(callerValue);
        }

        return pseudonymizer.scrubText(callerValue);
      });
    }
    if (key === 'payload') {
      // entity payloads are anonymized by the walker; scrub remaining free text
      // for embedded emails/phones/IBANs (activity payloads are arbitrary JSON)
      return scrubStringLeaves(transformNode(value, context), pseudonymizer);
    }

    return transformNode(value, context);
  });
};

export const scrubStringLeaves = (node: unknown, pseudonymizer: Pseudonymizer): unknown => {
  if (typeof node === 'string') {
    return pseudonymizer.scrubText(node);
  }
  if (Array.isArray(node)) {
    return node.map((item) => scrubStringLeaves(item, pseudonymizer));
  }
  if (isPlainObject(node)) {
    return mapEntries(node, (value) => scrubStringLeaves(value, pseudonymizer));
  }

  return node;
};

const isEntityLike = (record: Record<string, unknown>): boolean =>
  typeof record._schema === 'string' && ('_id' in record || '_org' in record || '_created_at' in record);

const isEntityOperationLike = (record: Record<string, unknown>): boolean =>
  typeof record.operation === 'string' && ('payload' in record || 'diff' in record) && 'activity_id' in record;

const isActivityLike = (record: Record<string, unknown>): boolean =>
  typeof record.type === 'string' &&
  typeof record.title === 'string' &&
  typeof record.message === 'string' &&
  'caller' in record;

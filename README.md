# @epilot/anonymization

Deterministic PII pseudonymization and redaction for [epilot](https://www.epilot.cloud) entity
data and arbitrary JSON.

Built for **data minimization**: AI agents, analytics pipelines, logs, and integrations usually
need the *shape* and *relationships* of business data — not the personal identifiers inside it.
This package removes the identifiers while keeping the data useful.

```
Max Mustermann          -> person_4f2a9b1c
max@web.de              -> 4f2a9b1c@anonymized.invalid
+49 170 1234567         -> +0083920174
DE89 3704 0044 ...      -> iban_7c01d2aa
Musterstr. 12b, 50667 Köln, DE
                        -> street_9e44aa01, 50667 Köln, DE
1985-06-14 (birthdate)  -> 1985-01-01
"Divorced, two kids"    -> [REDACTED]
```

It is the shared implementation behind epilot's **anonymized API responses**
(`?anonymize=true` / access tokens minted with `anonymize: true`) and is designed to be used
anywhere entity data travels: webhook payloads, ERP integrations, audit logs, datalake
ingestion, and LLM prompt assembly.

---

## Our commitment

This package encodes how epilot treats personal data, in public, reviewable code:

- **Data minimization by default.** Consumers of business data should receive exactly as much
  personal data as their purpose requires — usually none. This library makes "none" easy.
- **AI safety as an architecture property, not a prompt.** Large language models should not see
  end-customer PII unless the feature strictly requires it. epilot's AI agents request
  anonymized data at the *token level*, enforced server-side — model-side guardrails are
  defense-in-depth, never the primary control.
- **No security by obscurity.** The full masking logic — including the curated list of what we
  classify as PII — is open source and versioned. Anyone (customers, data protection officers,
  auditors) can review exactly what is masked, how, and what is not. All security rests on the
  HMAC secret you inject ([Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle)).
- **Fail safe, never open.** No secret configured → static redaction, never raw pass-through.
  Schema lookup failed → field-name defaults still apply. Inputs are never mutated; the package
  never logs values, phones home, or persists anything.
- **Honesty about limits.** This is *pseudonymization*, not anonymization in the strict GDPR
  Art. 4(5) sense — see [Limitations](#limitations-read-this) below. We would rather you know.

## Install

```sh
npm install @epilot/anonymization
```

Zero runtime dependencies. Node.js ≥ 18. Runs in Lambdas and sandboxed runtimes.

## Usage

### Create an anonymizer

```ts
import { createAnonymizer } from '@epilot/anonymization';

const anonymizer = createAnonymizer({
  orgId: '123',
  // Inject from a secret store (e.g. SSM). Omitting it fails safe to static redaction.
  secret: process.env.ANONYMIZATION_SECRET,
  // Optional: extend the curated defaults
  overrides: { 'mycustom:internal_note': 'redact' },
});
```

### Schema-aware entity mode

For epilot entities, when the entity schema is available (or resolvable). Classification uses,
in order: the attribute's `data_classification` (`'public'` opt-out / `'pii'` opt-in), your
`overrides`, the curated defaults, then attribute-type defaults (`email`, `phone`, `address`,
`payment`).

```ts
// single entity (or a partial entity, e.g. an activity diff)
const safeContact = anonymizer.anonymizeEntity({ entity: contact, schema: contactSchema });

// any JSON document containing entities — API responses, event payloads, activity feeds.
// Schemas are resolved via an injected resolver; entity-shaped objects, operation
// payloads/diffs, and activity records are found and anonymized recursively.
const safeResponse = await anonymizer.anonymizeResponse(searchResponse, {
  schemaResolver: async ({ orgId, slug }) => entityClient.getSchema(slug), // or a static map
});
```

### Non-schema-aware mode

For contexts without entity schemas: audit logs, integration monitoring records, inbound
webhook/ERP events, arbitrary JSON.

```ts
// field-name heuristics (first_name, email, iban, password, ...) + pattern scrubbing
const safeEvent = anonymizer.anonymizeUnknown(inboundWebhookEvent);

// strict: additionally redact EVERY unrecognized string leaf (for long-retention logs)
const safeAuditRecord = anonymizer.anonymizeUnknown(auditRecord, { strict: true });

// lightest touch: only replace emails/phones/IBANs embedded in strings, idempotent
const safeLogLine = anonymizer.scrub(errorMessage);
```

### Enforcing the epilot `anonymize` token claim

Services with their own data stores can honor the same claim entity-api enforces:

```ts
import { hasAnonymizeClaim } from '@epilot/anonymization';

if (hasAnonymizeClaim(jwtClaims)) {
  response = await anonymizer.anonymizeResponse(response, { schemaResolver });
}
```

The claim is one-way by design: request input can opt *into* anonymization, never out of it.

## How pseudonyms work

`HMAC-SHA256(secret, orgId + kind + normalize(value))`, truncated — giving pseudonyms that are:

- **stable within an organization**: the same customer yields the same pseudonym across
  requests, services, and time — joins, grouping, deduplication, and longitudinal analysis
  keep working;
- **different across organizations**: no cross-tenant correlation is possible;
- **one-way**: recovering the original value requires the secret, which you control and which
  never leaves your infrastructure.

Services that need *joinable* pseudonyms must share the same secret; services that don't
(e.g. isolated log scrubbing) should use their own to reduce blast radius. Rotating the secret
changes all pseudonyms.

## Limitations — read this

Being upfront about what this package does **not** do is part of its job:

1. **Pseudonymization ≠ anonymization.** Under GDPR Art. 4(5), deterministic pseudonymized data
   is still personal data, because the mapping is re-derivable with the secret. Treat outputs
   accordingly in your DPA assessments. (Static redaction via `strict` mode is stronger but
   destroys utility.)
2. **Free text is opt-in by default.** Unclassified free-text fields pass through in
   schema-aware mode (masking them all would destroy utility). Well-known risky fields
   (note/message content, opportunity descriptions, …) are covered by the curated defaults, and
   organizations opt further fields in with `data_classification: 'pii'`. Users can still type
   PII into fields nobody classified.
3. **Heuristics are best-effort.** The non-schema mode catches common field names and
   email/phone/IBAN patterns. Novel field names or unusual formats can slip through — use
   `strict: true` where that is unacceptable.
4. **Quasi-identifier re-identification.** Kept generalized values (postal code + city +
   birth year + consumption data) can, in small populations, narrow down individuals. If you
   publish datasets, apply k-anonymity-style analysis downstream.
5. **This library does not control queries.** If a caller can search by exact PII values
   upstream, they can probe (they must already know the value). Combine anonymized access with
   read-only, scoped credentials.

## What gets masked

The complete classification — strategies per attribute type and the curated field list — lives
in [`src/defaults.ts`](./src/defaults.ts) as plain reviewable data. Changes to it are made by
pull request and ship as minor releases, so a version bump is an auditable change to "what
counts as PII".

| Data | Strategy |
|---|---|
| Names (`first_name`, contact `_title`, …) | `person` pseudonym |
| Company names, tax/registration ids | `company` / `value` pseudonym |
| Emails, phones, IBANs (typed or by field name) | format-preserving pseudonyms |
| Addresses | keep postal code / city / country; pseudonymize street; drop the rest |
| Birthdates, PII-flagged dates | truncate to year |
| Payment items | pseudonymize IBAN/holder; keep bank name / BIC |
| User-relation attributes (`relation_user`, e.g. `contact_owner`) | pseudonymize name/email, **redact credentials** (`token`, `password`, …), keep ids/status/settings |
| Curated free-text (note/message content, opportunity description, …) | `[REDACTED]` |
| `data_classification: 'pii'` fields | pseudonym (single-line) / `[REDACTED]` (multiline) |
| Everything else | unchanged |

## Development

```sh
npm install
npm test        # vitest
npm run build   # tsc -> dist/
```

## Security

Please report vulnerabilities responsibly — see [SECURITY.md](./SECURITY.md). Do not open
public issues for security reports.

## License

[MIT](./LICENSE) © epilot GmbH

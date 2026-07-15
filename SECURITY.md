# Security Policy

`@epilot/anonymization` is a data-protection component: weaknesses in it can directly affect
the privacy of end customers. We treat every report seriously.

## Reporting a vulnerability

- **Preferred**: use GitHub's private vulnerability reporting on this repository
  ("Security" → "Report a vulnerability").
- Please do **not** open public issues or pull requests for security problems, and do not
  include real personal data in reports — synthetic examples only.

We will acknowledge reports promptly, keep you informed, and credit reporters who wish to be
credited once a fix is released.

## What counts as a vulnerability here

Beyond the usual (dependency issues — there are no runtime dependencies — or code execution),
we explicitly consider the following in scope:

- **Masking bypasses**: any input on which a value classified as PII survives anonymization
  (e.g. a value shape that escapes the entity walker, an address/payment structure that leaks
  a field, a pattern the scrubber should catch but doesn't).
- **Determinism/derivation weaknesses**: anything that makes pseudonyms reversible or
  cross-org linkable without the secret (e.g. insufficient input domain separation).
- **Fail-open behavior**: any code path where an error or missing configuration results in raw
  values passing through instead of redaction.

## Out of scope

- The inherent properties documented in the README's *Limitations* section (pseudonymization is
  re-derivable with the secret; non-strict heuristics are best-effort; quasi-identifier
  re-identification in small populations).
- Security of the secret storage itself — the secret is injected by the consumer and never
  handled by this package beyond HMAC input.

## Supported versions

The latest published minor release receives security fixes. The curated classification
defaults are versioned data: security-relevant additions to them are released promptly as
minor versions.

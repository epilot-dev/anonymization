# @epilot/anonymizing-mcp-proxy (draft)

MCP gateway that sits between an AI client (Claude, …) and an upstream MCP server and runs every
tool result through [`@epilot/anonymization`](../README.md) before the model sees it.
First preset: **Fullstory MCP**, whose tool results include end-user `user_properties`
(names, emails, uids, custom vars) and Fullstory has no per-scope access level to turn that off.

```
Claude ──(proxy token)──▶ anonymizing-mcp-proxy ──(FS API key)──▶ api.eu1.fullstory.com/mcp/fullstory
       ◀── pseudonymized ──                      ◀── raw ─────────
```

## What it does

| Layer | Behavior |
| --- | --- |
| **Credentials** | Holds the Fullstory API key ([documented gateway mode](https://developer.fullstory.com/mcp/authentication/)); clients authenticate with their own revocable `PROXY_TOKENS`. Client headers (cookies, auth) never reach Fullstory. |
| **User property bags** | Any object under `user_properties` / `userVars` / `properties` / `traits` / … is anonymized **strictly**: known PII keys pseudonymized (`displayName` → `person_4f2a…`, `email` → `…@anonymized.invalid`, `uid` → `value_…`), every other string **redacted** unless allow-listed via `KEEP_USER_PROPERTIES` (e.g. `plan,role`). |
| **Everything else** | `anonymizeUnknown` field heuristics + Fullstory overrides (`displayName`, `uid`, `ip`, `latlong`, …) + pattern scrub of emails / phones / IBANs in all strings. |
| **URLs** | Query-string values & fragments redacted (`?search=REDACTED`), except links into `*.fullstory.com` (replay links stay clickable). |
| **Prose / markdown output** | `Key: value` lines get the same field heuristics; rest is pattern-scrubbed. |
| **Binary content** | Images / audio / blobs replaced with a placeholder (pixels can't be anonymized). |
| **Blocked tools** | `session_screenshot`, `session_get_a11y_tree`, `session_diff` hidden from `tools/list` and answered locally with `isError` — raw DOM/pixels. Override with `BLOCKED_TOOLS` / `ALLOWED_TOOLS`. |
| **Transport** | Streamable HTTP: JSON and SSE responses (event-by-event, ids preserved), `Mcp-Session-Id` passthrough. Unknown content types → 502, never passthrough. |
| **Logging** | Method, tool name, status, latency. Never bodies. |

Pseudonyms are deterministic (HMAC, `ANONYMIZATION_SECRET`), so the same user maps to the same
pseudonym across tool calls — the model can still correlate sessions, count distinct users, etc.

## Run

```sh
npm ci && npm run build
FULLSTORY_API_KEY=eu1.… PROXY_TOKENS=$(openssl rand -hex 24) ANONYMIZATION_SECRET=$(openssl rand -hex 32) npm start
```

See [`.env.example`](.env.example) for all options. Docker: `docker build -t fs-mcp-proxy . && docker run -p 8080:8080 --env-file .env fs-mcp-proxy`.

### Claude Code

```sh
claude mcp add --transport http fullstory https://<proxy-host>/mcp --header "Authorization: Bearer <proxy-token>"
```

### claude.ai (org connector)

claude.ai custom connectors don't take static headers: use the path-token form
`https://<proxy-host>/mcp/<proxy-token>` (treat the URL as a secret), or add OAuth in front
(see follow-ups).

## Limitations — read this

- **Heuristic, not a guarantee.** Novel property names outside a user-property bag, or names in
  free text (`"Max clicked Save"`), are not caught. Fullstory's own masking/exclusion rules stay the
  first line of defense — keep them tight; this proxy is the second.
- **Pseudonyms are one-way.** If the model asks Fullstory to filter by `person_4f2a…`, Fullstory
  won't find it. Filtering by raw PII was the thing we wanted to avoid anyway.
- **Upstream output format isn't contractually stable.** Tests use fixtures; validate against real
  `get_session_events` / `get_opportunity` output before rollout and extend the overrides.
- **Shared API key** = everyone behind the proxy has the key's Fullstory permissions. Use per-user
  proxy tokens so access can be revoked individually.

## Follow-ups before prod

1. Validate against live Fullstory MCP output (EU org), extend `src/fullstory.ts`.
2. Deploy (Lambda Function URL with response streaming, or ECS) with secrets from SSM.
3. OAuth 2.1 front door (e.g. epilot SSO / Cognito) instead of static tokens, for claude.ai.
4. Optional: request-side scrubbing of tool arguments.
5. Extract into its own repo (`epilot-dev/anonymizing-mcp-proxy`) — this folder is self-contained.

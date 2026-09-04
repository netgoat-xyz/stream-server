# NetGoat stream server

The stream server is NetGoat's small control plane. It reads domains, upstream
pools, WAF rules, users, zero-trust state, and agent runtime settings from
MongoDB, then exposes normalized snapshots for polling agents. If MongoDB is
unavailable, the last in-memory snapshot remains active and startup can fall
back to a local seed file.

Dashboard writes (ProxyConfig upstreams, TLS PEMs, domain `waf_rules`, and
`route_policy`) land in MongoDB. This service polls those documents and
publishes `GET /domains` for the NetGoat agent. The agent-facing JSON field is
**`policy`** (`cache` / `bandwidth`), not `route_policy`, so UI-managed route
policy reaches the agent without YAML. Snapshot fields stay within the Go
agent contract: `policy`, certs, targets, and `waf_rules`.

## Run it

Requirements: Bun 1.3 or newer and, optionally, MongoDB.

```bash
cp .env.example .env
bun install
bun run start
```

The server retries an unavailable MongoDB connection; it does not need MongoDB
to start. Keep `seed-data.json`, `.env`, TLS private keys, and API keys out of
version control.

## Authentication

Set `API_KEY`, `DIAMOND_KEY`, or both. Clients may authenticate with
`X-API-Key`, `Authorization: Bearer`, `X-Diamond-Key`, or the legacy
`X-Zero-Trust-Key` header. When no read key is configured, requests are denied
unless `ALLOW_UNAUTHENTICATED=true` is explicitly set.

`CONFIG_WRITE_KEY` is optional but recommended. When present, only that key can
update `/agent-config`; send it in `X-Config-Write-Key` or a supported auth
header. Without it, write access falls back to the normal API authentication.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` or `/health` | Liveness, Mongo status, and cached counts |
| `GET` | `/domains` | Active routes, TLS PEMs, per-route `policy`, upstreams, WAF rules, zero-trust state, and agent settings |
| `GET` | `/users` | Active, non-banned control-plane users |
| `GET` | `/agent-config` | Current normalized agent runtime settings |
| `PUT` | `/agent-config` | Validate and update agent runtime settings |

All JSON responses are marked `Cache-Control: no-store` because snapshots can
contain TLS private keys. Request bodies for configuration updates are limited
to 64 KiB.

WAF rules associated with a domain or proxy configuration include a normalized
`hosts` list in `/domains`. Agents combine that list with the rule expression,
so a route-specific rule cannot silently become global. Scoped rules whose
route no longer exists are omitted from the published snapshot.

## Seed data

`scripts/seed-mongo.ts` accepts the same top-level data shape served to agents:

```json
{
  "domains": [],
  "waf_rules": [],
  "users": [],
  "zero_trust_enabled": false,
  "agent_config": {}
}
```

Run `bun run scripts/seed-mongo.ts` to upsert records. Setting
`SEED_RESET=true` first clears only the replaceable `domains` and `waf_rules`
collections. It never drops unrelated collections or deletes application user
records.

## Verification

```bash
bun run test
bun run typecheck
```

The test suite covers snapshot filtering and upstream mapping, route `policy`
emission from Mongo `route_policy`, seed conversion, request-size and media-type
enforcement, secret redaction, model indexes, session expiry, invite lookup
isolation, and DNS validation.

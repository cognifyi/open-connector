# Fork patch ledger

Every divergence from `upstream/main` that is not itself an upstream PR gets a
row here. This is the checklist for the quarterly rebase: each row must either
still apply cleanly or be recorded as dropped/upstreamed.

| Area                                                                        | Change                                                                                                           | Status | Upstream PR                                        |
| --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------- |
| `.github/workflows/publish-ghcr.yml`                                        | New fork-only workflow; amd64 image to `ghcr.io/cognifyi/open-connector`                                         | active | — (publishing infra)                               |
| `fork/`                                                                     | This directory                                                                                                   | active | —                                                  |
| `migrations/0023+0024` (both dialects)                                      | `tenant_id` on all row-scoped tables + `subject`/`status`/`visibility` on connections + tenant-scoped PKs        | active | — (upstream is single-tenant)                      |
| `src/tenant/`                                                               | Tenant-id/subject grammar and validation; `tenant-scope.ts` explicit scope predicates                            | active | —                                                  |
| `src/server/storage/`                                                       | All tenant-scoped queries carry a `TenantScope`; `forTenant`/`forInstance` views on `RuntimeDatabase`            | active | —                                                  |
| `src/server/api/auth.ts` + `connect-app.ts`                                 | `readTenantId`/`readSubject` request resolution; instance-wide token auth; `services.forTenant` scoped graph     | active | —                                                  |
| `src/server/tenant-services.ts` + all request routes                        | Per-request `ScopedServices` bundle; every endpoint family resolved through `forTenant(readTenantId)`            | active | —                                                  |
| `src/server/api/tenant-isolation.test.ts` + storage `tenant-scope.cases.ts` | Cross-tenant isolation suite: endpoint-level negative/positive cases + per-backend store cases                   | active | —                                                  |
| `src/server/api/runtime-jwt.ts` + `auth.ts`                                 | Verified JWT resolves to a tenant-bound `RuntimeGrant` (org claim → `tenant_id`, `sub` → `jwt:<sub>`)            | active | —                                                  |
| `src/tenant/` + `connection-request-store`                                  | `requireTenantId` normalizes trim/lowercase; `ownerAliases` widens `service:admin` reads to `local-admin`        | active | —                                                  |
| `migrations/0026` + `runtime_tokens` grant envelope                         | `expires_at`/`run_id`/`audience_json` on tokens; `resolveToken` rejects expired; mint accepts envelope fields    | active | — (token TTL is upstreamable)                      |
| `src/server/runtime-maintenance.ts` + store sweep methods                   | Periodic hard-delete of expired grants; `findByAllowedConnection`/`revokeByRuntimeToken`/`deleteExpired`         | active | — (sweep is upstreamable)                          |
| `ConnectionService.onDisconnected` + disconnect cascade                     | Disconnect revokes (or `prune`s) runtime tokens referencing the connection + their OAuth tokens                  | active | — (cascade is upstreamable)                        |
| `ActionPolicyService.requireExplicitPolicy`                                 | `OOMOL_CONNECT_REQUIRE_EXPLICIT_POLICY` flips token actions/connections to deny-by-default                       | active | — (flag is upstreamable)                           |
| `IConnectServerOptions`                                                     | Removed post-OC-1 dead service options (stores/services now reach handlers via `services`/`runtimeDatabase`)     | active | —                                                  |
| `migrations/0027` + runs audit columns + `api/run-context.ts`               | `run_id`/`trace_id`/`grant_id`/`connection_id` on runs; grant-inherited run_id, W3C `traceparent`, NDJSON export | active | — (audit export is upstreamable)                   |
| `api/rate-limit.ts` + `api/run-context.ts` hardening                        | Per-(tenant,token) 429 limiter on `/v1`+`/mcp`; strict `x-oc-run-id`/`traceparent` validation                    | active | — (limiter is upstreamable)                        |
| `secrets/*-codec` fail-fast + `oauth/scope-policy.ts`                       | Encryption key required unless plaintext opt-in; `oc:*` scope→TokenPolicy compile; `*` connection wildcard       | active | encryption default upstreamable; scope syntax fork |

Fork-planned work packages (land as rows when merged):

- OC-1 `src/tenant/` — tenant_id/subject/status/visibility across all stores
- OC-2 `src/grant/` — runtime token TTL/run_id/audience, default-deny, cascade revoke
- OC-3 runs audit columns + NDJSON export (upstreamable)
- OC-4 hardened defaults + tenant rate limiting + scope→policy mapping

# Tenant model (OC-1)

In-repo multi-tenancy for the shared Pazity instance. Design source:
`plan/0.战役工单/07-2026-11-omni-brain演进/12-open-connector-development.md` §3.2.

## Grammar

- `tenant_id` — maps 1:1 to the Hub `org_id` (`src/tenant/tenant-id.ts`).
  Grammar `[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}`; `all` is reserved; `local` is the
  default tenant every pre-OC-1 row backfilled to and the only tenant a
  single-tenant dev instance ever sees.
- `subject` — connection ownership (`src/tenant/subject.ts`). Grammar
  `<kind>:<id>` with kinds `user` / `space` / `service`. Backfilled rows keep
  the legacy value `local-admin`, which is rejected as _new_ input.

## Schema (migration 0023, both dialects)

Tenant-scoped (got `tenant_id text not null default 'local'`):

| Table                                                                                                                                                 | Extra changes                                                                                                                                  |
| ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `connections`                                                                                                                                         | + `subject`, `status` (`active/expired/revoked/failed`), `visibility` (`private/service/shared`); PK → `(tenant_id, service, connection_name)` |
| `connection_retirements`                                                                                                                              | PK → `(tenant_id, service, connection_name)`                                                                                                   |
| `oauth_client_configs`                                                                                                                                | PK → `(tenant_id, service)` (org-level auth config)                                                                                            |
| `custom_mcp`                                                                                                                                          | PK → `(tenant_id, service)`; `name_key` stays globally unique                                                                                  |
| `provider_preferences`                                                                                                                                | PK → `(tenant_id, service)`                                                                                                                    |
| `idempotency_records`                                                                                                                                 | PK → `(tenant_id, key_hash)` (key_hash is caller-controlled; a global key would allow cross-tenant squatting/replay)                           |
| `trigger_source_applications`                                                                                                                         | PK → `(tenant_id, id)` in migration 0024 (`id` is a digest of caller input; a global PK would swallow another tenant's save)                   |
| `connection_requests`, `runtime_tokens`, `runs`, `trigger_subscriptions`, `oauth_states`, `oauth_authorization_codes`, `oauth_tokens`, `saas_cleanup` | column only                                                                                                                                    |     |

Instance-singleton (deliberately **not** tenant-scoped): `instance_identity`,
`managed_project`, `marketplace_config`, `runtime_policy`, `oauth_clients`,
`oauth_signing_keys`, `oauth_sources`.

## Storage scoping (OC-1b)

Scope is **explicit**, not ambient (`src/tenant/tenant-scope.ts`):

- `RuntimeDatabase.forTenant(tenantId)` returns a sibling view whose
  tenant-scoped stores are all bound to that tenant. `forInstance()` is the
  named escape hatch (`scope === null`) for cross-tenant maintenance —
  secret rotation, sweeps, `resetRuntimeData`, `SaasProjectStore` cleanup.
- The default view is bound to `local`, so pre-OC-1 single-tenant callers
  keep working unchanged; OC-1c binds request scope at the boundary instead.
- Stores compose predicates through `tenantPredicate` / `tenantWhere`
  (postgres: `tenantPredicatePg` / `tenantWherePg` with `$N` numbering) and
  stamp rows with `tenantForInsert`. A `null` scope degrades every predicate
  to `1 = 1` — there is no silent fallback to a tenant.
- Secret rotation (`rotateSecretCodec`) is instance-scoped and pairs every
  read row's `tenant_id` back into its `update` predicate, so same-named
  rows in different tenants are never overwritten by each other's value.

Cross-tenant coverage lives in `src/server/storage/tenant-scope.cases.ts`,
wired into all three backend suites: same-name connections, idempotency-key
reuse, OAuth state/code/token lookup, runtime tokens, run logs, client
configs, provider preferences, and the `forInstance()` escape hatch.

## Request boundary (OC-1c)

- `RuntimeTokenRecord`/`RuntimeGrant` carry `tenantId` read back from the
  `runtime_tokens.tenant_id` column, so a token authenticates **across**
  tenants (`forInstance()` hash lookup) and then binds the request to the
  tenant stamped at issuance (`src/server/storage/runtime-token-service.ts`).
- `readTenantId(context)` (`src/server/api/auth.ts`) resolves the request
  tenant: the bound grant's `tenantId` wins, admin bearer credentials (not console
  session cookies — cookie reads stay non-mutating) may select a tenant with `?tenant=` or `x-connect-tenant`, and everything else
  falls back to `local`. A grant that disagrees with an explicit selector
  gets `tenant_conflict` (403); a non-admin selector gets
  `tenant_forbidden`; invalid ids get `invalid_tenant_id` via
  `requireTenantId`. `TenantError` maps to `status`/`code` in
  `ConnectServer.onError`.
- Admin routes resolve scoped stores per request through
  `options.runtimeDatabase.forTenant(readTenantId(context))` —
  `/api/runtime-tokens` is the first consumer (`policy-routes.ts`); the
  `local` tenant keeps using the injected service so single-tenant wiring is
  unchanged.
- The request-facing service graph is a pure function of the runtime view:
  `services.forTenant(tenantId)` (`src/server/tenant-services.ts`,
  `connect-app.ts`) returns a sibling bundle where every tenant-scoped
  store is bound to that tenant. `local` resolves to the root bundle itself;
  other tenants build lazily and cache. Connection routes
  (connection, OAuth, SaaS, catalog, execution, MCP, trigger, run-log,
  marketplace, docs, custom-MCP and event-verification routes) consume the
  bundle per request.
- `readSubject(context)` stamps `connection_requests.owner`: runtime-token
  callers own flows as `service:<tokenId>`; every other credential shares
  the tenant's `service:admin` principal (the renamed `local-admin` — the
  legacy value still reads in old rows but is no longer written). Admin
  bearers may act on behalf via `?subject=`/`x-connect-subject`.
- The credential-free OAuth callback resolves its tenant from the pending
  `oauth_states` row (`tenantOf`, instance-wide) and completes inside that
  tenant's scoped bundle — a `?tenant=X` flow can finish end-to-end.
- Every request-facing route resolves `forTenant(readTenantId(context))` —
  actions, proxy, idempotency, triggers, MCP, run logs, custom MCP,
  marketplace preferences and event verification all run inside the grant's
  or selected tenant. The temporary fail-closed guard on non-`local` grants
  is lifted: a token minted under `?tenant=X` authenticates and executes in
  tenant X.
- The inbound OAuth authorization server binds grants to tenants per record:
  `oauth_clients`/`oauth_signing_keys` stay instance-global, code and token
  hash lookups run instance-wide (hashes are globally unique), and
  `oauth_authorization_codes`/`oauth_tokens` rows are written under the
  tenant that approved the grant — exchange and rotation rebind to
  `record.tenantId` before inserting successors, and grant revocation
  (token endpoint + client deletion) revokes each backing runtime token
  through its own tenant scope.
- Two public surfaces stay `local`-only by design for now: the browser
  consent form (`POST /oauth/mcp/authorize`) authenticates with the admin
  token in the form body rather than a bearer, so it always mints in
  `local`; channel event verification carries only the dedicated verify
  token (no grant), so it resolves `local` credentials. Tenant-bound
  channels need a tenant claim on the webhook credential path — later work.
- The instance-wide trigger sweep (`TriggerMaintenance.runBatch`) resolves
  each candidate's own service graph via `runnerFor(record.tenantId)`; the
  record carries `tenantId` decoded from the row.
- JWT-authenticated callers and browser sessions share the `service:admin`
  subject; only runtime-token (`service:<tokenId>`) and explicit
  `?subject=` (admin bearer) requests carry distinct owners. Admin can read a
  token-owned request only via `?subject=service:<tokenId>` — on-behalf
  completion is the intended protocol.
- Verified JWTs (Keycloak/Hub JWKS) resolve to a tenant-bound `RuntimeGrant`:
  the org claim (`org_id`/`orgId`/`tenant`/`tenant_id`, first present wins)
  maps to `tenant_id`, and `sub` becomes `tokenId: jwt-<sub>` (base64url
  fallback when `sub` is outside the subject grammar, so distinct subjects
  never collide). An absent claim binds `local` — unless
  `OOMOL_CONNECT_JWT_REQUIRE_ORG=true` is set for shared multi-tenant
  deployments, where a token with no org claim is rejected. An unparseable
  claim always fails closed. The grant's empty allow-lists match the OAuth
  grant policy shape (actions/triggers/connections open, proxies denied —
  same as every runtime credential).
- `requireTenantId` normalizes once at the boundary (trim + lowercase), so a
  JWT `Alpha-Team` claim, `?tenant=ALPHA`, and the `tenant_id` column can
  never disagree by casing. `isTenantId` stays strict — stored ids are always
  the normalized form.
- Runtime tokens carry a grant envelope (`expires_at`, `run_id`,
  `audience_json`) since migration 0026: `POST /api/runtime-tokens` accepts
  `expiresAt`/`runId`/`audience {type,id,onBehalfOf?}`; `resolveToken`
  fails closed once `expires_at` passes; both fields ride the `RuntimeGrant`
  so run/audit wiring (OC-3) and audience checks (OC-5) can consume them.
- Grant hygiene runs on two paths: `resolveToken` rejects expired grants
  immediately, and `RuntimeMaintenance` (60s tick on Node, `scheduled` on
  Workers) hard-deletes expired `runtime_tokens`/`oauth_tokens`/
  `oauth_authorization_codes` rows across every tenant via the instance view.
- Disconnecting a connection cascades into locally minted grants: every
  runtime token whose `allowedConnections` lists the deleted connection id
  is revoked (default) or pruned, chosen by
  `OOMOL_CONNECT_DISCONNECT_TOKEN_POLICY=revoke|prune`. Revocation also
  stamps `revoked_at` on OAuth access/refresh tokens minted on top of the
  grant (`revokeByRuntimeToken`). The cascade is tenant-scoped — the stores
  it runs through belong to the disconnecting request's tenant view.
- `OOMOL_CONNECT_REQUIRE_EXPLICIT_POLICY=true` flips token policy to
  deny-by-default for actions and connections (an empty `allowedActions`
  or `allowedConnections` on a token then grants nothing). Token proxies
  and triggers were always deny-by-default; the flag makes the whole grant
  surface uniform. Deployment/runtime allowlists keep "empty = no
  constraint", and requests carrying no grant at all are unaffected.
  Hardened deployments must mint tokens with explicit policies — and note
  that OAuth-AS-backed grants still mint with empty allow-lists until the
  OC-4 scope→policy mapping lands, so they deny everything under the flag.
- `service:admin` lookups widen to the legacy `local-admin` owner
  (`ownerAliases`): pre-OC-1 `connection_requests` rows remain reachable
  through the canonical subject, and supersession/cancel/claim match both
  spellings. New writes always use the `kind:id` grammar.

## Invariants for later OC-1 tasks

- Every query against a tenant-scoped table filters `tenant_id`; every write
  stamps it. Runtime tokens carry their tenant from issuance, so token-bound
  calls cannot cross tenants even if the management plane is misused.
- `status`/`visibility` are write-path managed; `shared` + ACL is M6-09 scope
  — OC-1 uses `private` and `service` only.
- Three-backend parity (`sqlite`/`postgres`/`d1`) is enforced by
  `migration-equivalence.test.ts` and the store `.cases.ts` suites.
- Cross-tenant isolation is enforced by `src/server/api/tenant-isolation.test.ts`
  (endpoint families against a real `createConnectApp` graph: runtime tokens,
  token↔tenant binding, connections/requests, OAuth client configs,
  idempotency keyspaces, run logs) and `tenant-scope.cases.ts` (per-backend
  store assertions including instance-scope maintenance views). Statements
  without a tenant predicate are instance-level by design: `resetRuntimeData`,
  `rotateSecretCodec`, hash lookups, maintenance sweeps, and the SaaS project
  accounting store. Transit files (`/api/files`) are also instance-level by
  design: ids are unguessable and TTL-bound; a file uploaded under one tenant
  is reachable by file id regardless of tenant.

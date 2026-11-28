# C16 direct JWT verification feasibility (OC-5)

> **Question (12 §8 Q3)**: should the Hub sign C16 grants as JWTs verified
> directly by OC against the Hub JWKS, or keep the current `oct_` runtime
> token mapping for M2-10a?
> **Verdict**: keep `oct_` mapping for M2-10a. JWKS direct verification is
> feasible with small, well-scoped work — tracked as follow-ups below.

## What exists today

- `src/server/api/runtime-jwt.ts` already verifies generic JWT access tokens
  against a configured JWKS (`OOMOL_CONNECT_JWKS_URI` /
  `OOMOL_CONNECT_JWT_ISSUER` / `OOMOL_CONNECT_JWT_AUDIENCE`), binds the token
  to a tenant through the org claim (`org_id`/`orgId`/`tenant`/`tenant_id`,
  normalized through `requireTenantId`), and mints a tenant-scoped
  `RuntimeGrant`. It is used for service JWTs, not for Hub grants.
- `src/grant/c16-policy.ts` (OC-5) compiles a C16 grant record into a
  `TokenPolicy` plus the mint envelope (`expiresAt`/`runId`/`audience`). It is
  deliberately transport-agnostic: it accepts a verified C16-shaped object no
  matter how the object arrived.
- `src/server/oauth/jwks.ts` signs and verifies OC's _own_ OAuth access
  tokens (ES256, persisted signing keys, rotation). It must not be confused
  with Hub-issued grant verification: different issuer, different audience,
  different key set.

## What direct C16 JWT verification would take

1. **Hub signs C16 as JWT.** C16 today is a JSON record (`connection-grant/v1`
   schema), not a JWT. The Hub would need to issue `grant JWTs` with claims
   carrying at least: `grantId` (`jti`), `connectionId`, `scopes`,
   `audienceType`/`audienceId`, `runId`, `onBehalfOf`, `epoch`, `exp`/`iat`,
   and the org claim for tenant binding. No OC change is needed for this step,
   but the claim names must be frozen in the contract (a C16-JWT profile), or
   OC ends up tracking Hub claim renames.
2. **OC verifies against the Hub JWKS.** `runtime-jwt.ts` already does
   signature + `iss`/`aud` + `exp` verification through `jose`
   `createRemoteJWKSet`. A C16-JWT verifier reuses that path with a Hub-bound
   config (issuer = Hub, audience = OC) and then feeds the verified claims
   into `compileC16GrantPolicy`. Estimated: one small module plus tests; no new
   dependencies (`jose` stays lazy-imported, satisfying the eager-import
   guard).
3. **Revocation gap.** A verified JWT is valid until `exp` even after the Hub
   revokes the grant, unless OC checks back. Options, in increasing cost:
   - short `exp` (≤15 min, already the C16 default) so the window matches the
     TTL backstop;
   - Hub epoch bump + OC epoch tracking per `(tenant, connection)` — OC has
     no Hub-epoch store today, so this is new state and new invalidation
     plumbing;
   - OC-side revocation list fed by Hub revoke callbacks.
     The `oct_` mapping has no such gap: revoke deletes the token row and
     `resolveToken` fails immediately, with the TTL sweeper as backstop.
4. **Run/connection binding gap.** The compiler binds `runId` and one
   `connectionRef`, but OC cannot independently verify that the Hub `runId`
   belongs to the calling run or that `con_*` names the same account as the
   OC connection row. With `oct_` mapping the Hub performs that check at mint
   time (it owns both sides); with direct JWTs the check moves to request
   time and needs a Hub run/connection lookup or a mirrored id map.

## Recommendation

- **M2-10a: stay on `oct_` mapping.** The Hub resolves `(subject, app,
  scopes)` → connection, compiles the C16 grant through `c16-policy.ts`,
  mints an `oct_` token under the caller's tenant, and revokes it when the
  run ends. Revocation is immediate, audit joins on `run_id`/`grant_id`, and
  no new cross-service state is needed.
- **Later, if direct JWTs are wanted** (fewer mint round-trips on hot paths):
  freeze the C16-JWT claims profile in the contract first, then add the
  verifier as a thin adapter over `runtime-jwt.ts` + `c16-policy.ts`, gated
  behind short `exp` so the revocation window never exceeds today's TTL
  backstop. Epoch tracking stays out until a measured need appears.

## Test hooks left for that work

- `src/grant/c16-policy.test.ts` pins the claim→policy mapping, so a future
  JWT adapter only needs to prove "JWT claims → verified C16 object"; the
  policy semantics are already covered.
- `src/server/api/runtime-jwt.ts` behavior (org-claim tenant binding,
  `requireOrgClaim` fail-closed mode) is the reference for how the Hub-JWT
  tenant binding must behave.

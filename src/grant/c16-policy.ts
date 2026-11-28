import type { TokenPolicy } from "../core/action-policy.ts";
import type { TokenAudience } from "../server/storage/runtime-token-service.ts";

import { requireTenantId } from "../tenant/tenant-id.ts";

/**
 * Compile a Hub C16 connection grant into the runtime token policy (OC-5).
 *
 * The Hub owns scope *semantics* (which toolkit scopes a subject was granted);
 * open-connector owns *enforcement* of the resulting token. This module is the
 * single place where the two meet: a C16 grant in, a {@link TokenPolicy} plus
 * the grant envelope (`expiresAt`/`runId`/`audience`) accepted by
 * `POST /api/runtime-tokens` out. The minter (M2-10a Hub provider) calls this
 * before minting the `oct_` token, so every Hub-issued token carries an
 * explicit allow-list and the run binding the audit trail joins on.
 *
 * Mapping rules (v1):
 * - `allowedConnections` binds exactly one OC-side connection. By default it
 *   is the grant's `connectionId`; pass `connectionRef` when the Hub
 *   connection id differs from the OC connection row id.
 * - `*` and the coarse verbs `read`/`write`/`admin` expand to
 *   `<toolkit>.*`. OC policy has no read/write dimension, so verb-level
 *   protection for read grants stays Hub-side at execute time — the same
 *   posture as the Composio path. The expansion is toolkit-scoped: a grant
 *   for `github` can never authorize `notion.*`.
 * - Scopes already shaped `<toolkit>.<action>` (or `*`) pass through verbatim
 *   after syntax validation.
 * - `oc:actions:<pattern>` strips the prefix and keeps the validated pattern,
 *   aligning the OAuth AS scope grammar (OC-4) with C16 scopes.
 * - Anything else (e.g. `repo:read`) is namespaced to
 *   `<toolkit>.<scope>`: it matches no real action unless a provider defines
 *   that id, so unknown scopes deny by default instead of granting.
 *
 * Everything fails closed: expired grants, non-`active` status, empty scopes,
 * cross-service scopes, and unparseable instants throw {@link C16PolicyError}
 * instead of minting a permissive token.
 */

export class C16PolicyError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "C16PolicyError";
    this.code = code;
  }
}

/** The Hub-issued C16 `connection-grant/v1` record (JSON form). */
export interface C16Grant {
  grantId: string;
  connectionId: string;
  audienceType: "agent" | "run" | "service" | "session";
  audienceId: string;
  runId: string;
  scopes: readonly string[];
  onBehalfOf: string;
  expiresAt: string;
  epoch: number;
  issuedAt: string;
  status?: string;
}

export interface C16CompileOptions {
  /** OC service name the grant is for (e.g. `github`). Scopes are bound to it. */
  toolkit: string;
  /** Hub org id the token is minted under; normalized through tenant grammar. */
  tenantId: string;
  /**
   * OC-side connection id to bind when it differs from the Hub
   * `connectionId` (e.g. Hub `con_*` vs the OC connection row id).
   * Defaults to `grant.connectionId`.
   */
  connectionRef?: string;
  /** Clock for expiry checks; defaults to `Date.now()`. Tests pin it. */
  now?: number;
}

export interface C16CompiledPolicy {
  policy: TokenPolicy;
  envelope: {
    expiresAt: string;
    runId: string;
    audience: TokenAudience;
  };
  /** Normalized tenant the token must be minted under. */
  tenantId: string;
}

const AUDIENCE_TYPES = new Set(["agent", "run", "service", "session"]);
const COARSE_VERBS = new Set(["read", "write", "admin"]);
const TOOLKIT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;
const ACTION_SCOPE_PREFIX = "oc:actions:";
const MAX_ID_LENGTH = 256;

function requireId(field: string, value: unknown): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new C16PolicyError("invalid_grant", `C16 grant ${field} must be a non-empty string.`);
  }
  const id = value.trim();
  if (id.length > MAX_ID_LENGTH) {
    throw new C16PolicyError("invalid_grant", `C16 grant ${field} must not exceed ${MAX_ID_LENGTH} chars.`);
  }
  return id;
}

function requireInstant(field: string, value: unknown): string {
  const instant = requireId(field, value);
  if (Number.isNaN(Date.parse(instant))) {
    throw new C16PolicyError("invalid_grant", `C16 grant ${field} must be an ISO-8601 instant string.`);
  }
  return instant;
}

function isValidActionPattern(pattern: string): boolean {
  if (pattern === "*") {
    return true;
  }
  if (pattern.includes("*") && !/^[^\s.*]+\.\*$/.test(pattern)) {
    return false;
  }
  if (/\s/.test(pattern)) {
    return false;
  }
  const separator = pattern.indexOf(".");
  return separator > 0 && separator < pattern.length - 1;
}

function mapScope(scope: string, toolkit: string): string {
  if (scope === "*") {
    return `${toolkit}.*`;
  }
  if (scope.startsWith("oc:")) {
    if (!scope.startsWith(ACTION_SCOPE_PREFIX)) {
      throw new C16PolicyError(
        "unsupported_scope",
        `C16 grant carries unsupported connector scope ${JSON.stringify(scope)}.`,
      );
    }
    const pattern = scope.slice(ACTION_SCOPE_PREFIX.length);
    if (!isValidActionPattern(pattern)) {
      throw new C16PolicyError(
        "invalid_scope",
        `C16 grant carries malformed oc:actions scope ${JSON.stringify(scope)}.`,
      );
    }
    return pattern;
  }
  if (COARSE_VERBS.has(scope)) {
    return `${toolkit}.*`;
  }
  if (/\s/.test(scope) || scope.length === 0) {
    throw new C16PolicyError("invalid_scope", `C16 grant carries an invalid scope ${JSON.stringify(scope)}.`);
  }
  if (isValidActionPattern(scope)) {
    if (scope.startsWith(`${toolkit}.`) || scope === "*") {
      return scope;
    }
    throw new C16PolicyError(
      "cross_service_scope",
      `C16 grant for ${toolkit} carries another service's scope ${JSON.stringify(scope)}.`,
    );
  }
  return `${toolkit}.${scope}`;
}

export function compileC16GrantPolicy(grant: C16Grant, options: C16CompileOptions): C16CompiledPolicy {
  if (typeof grant !== "object" || grant === null) {
    throw new C16PolicyError("invalid_grant", "C16 grant must be an object.");
  }
  if (typeof options !== "object" || options === null) {
    throw new C16PolicyError("invalid_grant", "C16 compile options must be an object.");
  }
  const toolkit = typeof options.toolkit === "string" ? options.toolkit.trim() : "";
  if (!TOOLKIT_PATTERN.test(toolkit)) {
    throw new C16PolicyError("invalid_toolkit", `C16 grant toolkit must match ${TOOLKIT_PATTERN}.`);
  }
  const tenantId = requireTenantId(options.tenantId);

  const now = options.now ?? Date.now();
  const status = grant.status ?? "active";
  if (status !== "active") {
    throw new C16PolicyError("grant_not_active", `C16 grant status is ${JSON.stringify(status)}, expected "active".`);
  }
  if (!Number.isInteger(grant.epoch) || (grant.epoch as number) < 1) {
    throw new C16PolicyError("invalid_grant", "C16 grant epoch must be an integer >= 1.");
  }
  const expiresAt = requireInstant("expiresAt", grant.expiresAt);
  // Canonicalize: the sweep compares `expires_at <= ?` as text, so a valid
  // but offset-dotted form must never reach the store (same discipline as
  // RuntimeTokenService.createToken).
  const expiresIso = new Date(expiresAt).toISOString();
  if (Date.parse(expiresIso) <= now) {
    throw new C16PolicyError("grant_expired", "C16 grant expiresAt is not in the future.");
  }
  requireInstant("issuedAt", grant.issuedAt);

  const grantId = requireId("grantId", grant.grantId);
  const runId = requireId("runId", grant.runId);
  const connectionId = requireId("connectionId", grant.connectionId);
  const audienceId = requireId("audienceId", grant.audienceId);
  const onBehalfOf = requireId("onBehalfOf", grant.onBehalfOf);
  if (!AUDIENCE_TYPES.has(grant.audienceType)) {
    throw new C16PolicyError("invalid_grant", "C16 grant audienceType must be one of agent|run|service|session.");
  }

  if (!Array.isArray(grant.scopes) || grant.scopes.length === 0) {
    throw new C16PolicyError("empty_scopes", "C16 grant scopes must be a non-empty array.");
  }
  const seen = new Set<string>();
  const allowedActions: string[] = [];
  for (const raw of grant.scopes) {
    if (typeof raw !== "string") {
      throw new C16PolicyError("invalid_scope", "C16 grant scopes must be strings.");
    }
    const mapped = mapScope(raw.trim(), toolkit);
    if (!seen.has(mapped)) {
      seen.add(mapped);
      allowedActions.push(mapped);
    }
  }

  const connectionRef =
    options.connectionRef === undefined ? connectionId : requireId("connectionRef", options.connectionRef);

  return {
    policy: {
      allowedActions,
      blockedActions: [],
      allowedProxies: [],
      allowedConnections: [connectionRef],
    },
    envelope: {
      expiresAt: expiresIso,
      runId,
      audience: { type: grant.audienceType, id: audienceId, onBehalfOf },
    },
    tenantId,
  };
}

import type { RuntimeGrant } from "../storage/runtime-token-service.ts";

import { DEFAULT_TENANT_ID, requireTenantId } from "../../tenant/tenant-id.ts";

export interface RuntimeJwtConfig {
  jwksUri?: string;
  issuer?: string;
  audience?: string;
}

/**
 * Verified JWT → runtime grant. The grant carries the token's tenant (an org
 * claim, normalized through the same grammar as `?tenant=`) and a stable
 * `service:jwt:<sub>` identity; a missing org claim binds `local`, preserving
 * the single-tenant behavior pre-OC-1 deployments rely on.
 */
export type RuntimeJwtVerifier = (token: string) => Promise<RuntimeGrant | undefined>;

/**
 * Creates a JWT access-token verifier when all runtime JWT settings are configured.
 * jose is imported only once the settings pass validation, so a runtime without JWT authentication never loads it.
 */
export async function createRuntimeJwtVerifier(config: RuntimeJwtConfig): Promise<RuntimeJwtVerifier | undefined> {
  const jwksUri = config.jwksUri?.trim();
  const issuer = config.issuer?.trim();
  const audience = config.audience?.trim();
  if (!jwksUri && !issuer && !audience) {
    return undefined;
  }

  if (!jwksUri || !issuer || !audience) {
    const missing = [
      ["OOMOL_CONNECT_JWKS_URI", jwksUri],
      ["OOMOL_CONNECT_JWT_ISSUER", issuer],
      ["OOMOL_CONNECT_JWT_AUDIENCE", audience],
    ]
      .filter(([, value]) => !value)
      .map(([name]) => name);
    throw new Error(`Runtime JWT authentication settings must be configured together; missing: ${missing.join(", ")}.`);
  }

  let url: URL;
  try {
    url = new URL(jwksUri);
  } catch {
    throw new Error("OOMOL_CONNECT_JWKS_URI must be a valid HTTPS URL or HTTP loopback URL.");
  }
  if (url.protocol !== "https:" && !isLoopbackHttpUrl(url)) {
    throw new Error("OOMOL_CONNECT_JWKS_URI must be a valid HTTPS URL or HTTP loopback URL.");
  }

  const { createRemoteJWKSet, jwtVerify } = await import("jose");
  const jwks = createRemoteJWKSet(url);
  return async (token) => {
    try {
      const { payload } = await jwtVerify(token, jwks, { issuer, audience, requiredClaims: ["exp"] });
      const sub = typeof payload.sub === "string" && payload.sub.trim() ? payload.sub : "anonymous";
      return {
        tokenId: `jwt:${sub}`,
        tenantId: readTenantClaim(payload),
        allowedActions: [],
        blockedActions: [],
        allowedProxies: [],
      };
    } catch {
      return undefined;
    }
  };
}

function isLoopbackHttpUrl(url: URL): boolean {
  if (url.protocol !== "http:") {
    return false;
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/u, "");
  return hostname === "localhost" || hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/u.test(hostname);
}

/**
 * Reads the tenant binding from a verified JWT payload. Accepts the org claim
 * names the Hub/Keycloak side uses (`org_id`, `orgId`, `tenant`, `tenant_id`);
 * an invalid value rejects the token outright rather than falling back.
 */
function readTenantClaim(payload: Record<string, unknown>): string {
  const raw = payload.org_id ?? payload.orgId ?? payload.tenant ?? payload.tenant_id;
  if (raw === undefined || raw === null) return DEFAULT_TENANT_ID;
  if (typeof raw !== "string") throw new Error("JWT org claim must be a string.");
  return requireTenantId(raw);
}

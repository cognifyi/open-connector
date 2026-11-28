import type { TokenPolicy } from "../../core/action-policy.ts";
import type { RuntimeLogger } from "../../core/types.ts";

import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { DEFAULT_TENANT_ID } from "../../tenant/tenant-id.ts";

/** C16 grant audience: which kind of principal the token acts for. */
export interface TokenAudience {
  type: "agent" | "run" | "service" | "session";
  id: string;
  onBehalfOf?: string;
}

/**
 * Fail-closed expiry check: an absent `expiresAt` never expires (pre-OC-2
 * rows), but a value that cannot be parsed is treated as expired rather than
 * granting a permanent token.
 */
export function isTokenExpired(record: { expiresAt?: string }, now: number = Date.now()): boolean {
  if (record.expiresAt === undefined) return false;
  const instant = Date.parse(record.expiresAt);
  return Number.isNaN(instant) || instant <= now;
}

export interface RuntimeTokenRecord {
  id: string;
  name: string;
  /** Tenant the token grants runtime access to; `local` for pre-OC-1 rows. */
  tenantId: string;
  tokenHash: string;
  allowedActions: string[];
  blockedActions: string[];
  allowedProxies: string[];
  allowedConnections: string[];
  allowedTriggers?: string[];
  createdAt: string;
  lastUsedAt?: string;
  /** ISO instant after which `resolveToken` rejects the token; absent = no expiry (pre-OC-2 rows). */
  expiresAt?: string;
  /** Omni run the grant is bound to; audit join key. */
  runId?: string;
  /** C16 audience descriptor for the grant. */
  audience?: TokenAudience;
}

export interface RuntimeTokenSummary {
  id: string;
  name: string;
  tenantId: string;
  allowedActions: string[];
  blockedActions: string[];
  allowedProxies: string[];
  allowedConnections: string[];
  allowedTriggers?: string[];
  createdAt: string;
  lastUsedAt?: string;
  expiresAt?: string;
  runId?: string;
  audience?: TokenAudience;
}

export interface RuntimeTokenCreation {
  token: string;
  record: RuntimeTokenRecord;
}

export interface IRuntimeTokenStore {
  add(record: RuntimeTokenRecord): Promise<void>;
  hasAny(): Promise<boolean>;
  list(): Promise<RuntimeTokenRecord[]>;
  findByHash(tokenHash: string): Promise<RuntimeTokenRecord | undefined>;
  findById(id: string): Promise<RuntimeTokenRecord | undefined>;
  /** Tokens whose `allowedConnections` list mentions `connectionId`; used by the disconnect cascade. */
  findByAllowedConnection(connectionId: string): Promise<RuntimeTokenRecord[]>;
  updatePolicy(id: string, policy: TokenPolicy): Promise<RuntimeTokenRecord | undefined>;
  revoke(id: string): Promise<boolean>;
  markUsed(id: string, usedAt: string): Promise<void>;
  /** Hard-delete rows whose `expires_at` has passed. Returns the deleted count. */
  deleteExpired(nowIso: string): Promise<number>;
}

const tokenPrefix = "oct_";

export interface RuntimeGrant extends TokenPolicy {
  tokenId: string;
  /** Tenant the grant is bound to; every runtime store lookup must run under `forTenant(grant.tenantId)`. */
  tenantId: string;
  expiresAt?: string;
  runId?: string;
  audience?: TokenAudience;
}

export class RuntimeTokenService {
  private readonly store: IRuntimeTokenStore;
  private readonly logger?: RuntimeLogger;
  private readonly tenantId: string;

  constructor(store: IRuntimeTokenStore, logger?: RuntimeLogger, tenantId: string = DEFAULT_TENANT_ID) {
    this.store = store;
    this.logger = logger;
    this.tenantId = tenantId;
  }

  async createToken(
    name: string,
    policy: TokenPolicy = {
      allowedActions: [],
      blockedActions: [],
      allowedProxies: [],
      allowedConnections: [],
    },
    envelope: { expiresAt?: string; runId?: string; audience?: TokenAudience } = {},
  ): Promise<RuntimeTokenCreation> {
    if (envelope.expiresAt !== undefined && Number.isNaN(Date.parse(envelope.expiresAt))) {
      throw new Error("expiresAt must be an ISO-8601 instant string.");
    }
    // Store the canonical ISO instant: `expires_at <= ?` is a text compare,
    // so a valid-but-offset form like "+02:00" would mis-order.
    const expiresAt = envelope.expiresAt === undefined ? undefined : new Date(envelope.expiresAt).toISOString();
    const token = `${tokenPrefix}${randomBytes(32).toString("base64url")}`;
    const now = new Date().toISOString();
    const record: RuntimeTokenRecord = {
      id: randomUUID(),
      name: name.trim(),
      tenantId: this.tenantId,
      tokenHash: hashRuntimeToken(token),
      allowedActions: policy.allowedActions,
      blockedActions: policy.blockedActions,
      allowedProxies: policy.allowedProxies,
      allowedConnections: policy.allowedConnections ?? [],
      allowedTriggers: policy.allowedTriggers ?? [],
      createdAt: now,
      expiresAt,
      runId: envelope.runId,
      audience: envelope.audience,
    };
    await this.store.add(record);
    return { token, record };
  }

  async listTokens(): Promise<RuntimeTokenSummary[]> {
    return (await this.store.list()).map(summarizeRuntimeToken);
  }

  async revokeToken(id: string): Promise<boolean> {
    return this.store.revoke(id);
  }

  async updateTokenPolicy(id: string, policy: TokenPolicy): Promise<RuntimeTokenSummary | undefined> {
    const record = await this.store.updatePolicy(id, policy);
    return record ? summarizeRuntimeToken(record) : undefined;
  }

  async resolveToken(token: string): Promise<RuntimeGrant | undefined> {
    if (!token.startsWith(tokenPrefix)) {
      return undefined;
    }
    const tokenHash = hashRuntimeToken(token);
    const matched = await this.store.findByHash(tokenHash);
    if (!matched || !equalHashes(matched.tokenHash, tokenHash)) {
      return undefined;
    }

    if (isTokenExpired(matched)) {
      return undefined;
    }

    await this.recordLastUsed(matched.id);
    return {
      tokenId: matched.id,
      tenantId: matched.tenantId,
      allowedActions: matched.allowedActions,
      blockedActions: matched.blockedActions,
      allowedProxies: matched.allowedProxies,
      allowedConnections: matched.allowedConnections ?? [],
      allowedTriggers: matched.allowedTriggers ?? [],
      expiresAt: matched.expiresAt,
      runId: matched.runId,
      audience: matched.audience,
    };
  }

  async verifyToken(token: string): Promise<boolean> {
    return Boolean(await this.resolveToken(token));
  }

  /**
   * `last_used_at` is best-effort audit metadata, so a failed write is logged
   * instead of turning an authenticated caller into a failed request.
   */
  private async recordLastUsed(tokenId: string): Promise<void> {
    try {
      await this.store.markUsed(tokenId, new Date().toISOString());
    } catch (error) {
      this.logger?.warn({ tokenId, err: error }, "runtime token last use update failed");
    }
  }
}

export function hashRuntimeToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

export function summarizeRuntimeToken(record: RuntimeTokenRecord): RuntimeTokenSummary {
  return {
    id: record.id,
    name: record.name,
    tenantId: record.tenantId,
    allowedActions: record.allowedActions,
    blockedActions: record.blockedActions,
    allowedProxies: record.allowedProxies,
    allowedConnections: record.allowedConnections,
    allowedTriggers: record.allowedTriggers ?? [],
    createdAt: record.createdAt,
    lastUsedAt: record.lastUsedAt,
    expiresAt: record.expiresAt,
    runId: record.runId,
    audience: record.audience,
  };
}

function equalHashes(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

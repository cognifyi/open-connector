import type { Context } from "hono";

import { readRuntimeGrant, readTenantId } from "./auth.ts";
import { jsonError } from "./http-utils.ts";
import { writeRuntimeFailure } from "./runtime-api.ts";

export interface RateLimitConfig {
  /** Sustained requests per minute per (tenant, token) bucket. `0` or less disables limiting. */
  rpm: number;
  /** Maximum burst capacity per bucket. */
  burst: number;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

const IDLE_SWEEP_MS = 10 * 60 * 1000;
const MAX_BUCKETS = 10_000;
const EXEMPT_PATH = /^\/v1\/(health|providers\/[^/]+\/events\/verify)$/;

/** djb2 — bucket keys only need to distinguish callers, not resist forgery. */
function hashBearer(token: string): string {
  let hash = 5381;
  for (let i = 0; i < token.length; i++) {
    hash = ((hash << 5) + hash + token.charCodeAt(i)) >>> 0;
  }
  return hash.toString(36);
}

function bucketKey(context: Context): string {
  const tenant = readTenantId(context);
  const grant = readRuntimeGrant(context);
  if (grant) {
    return `${tenant}\ngrant:${grant.tokenId}`;
  }
  const bearer = context.req.header("authorization")?.match(/^bearer\s+(\S+)/i)?.[1];
  return `${tenant}\n${bearer ? `bearer:${hashBearer(bearer)}` : "anonymous"}`;
}

/**
 * Token bucket per `(tenant_id, token_id)` on the runtime execution surface.
 * In-memory and instance-local by design: buckets reset on restart and are
 * not shared across replicas — the limit is a DoS guard, not an accounting
 * boundary. Health and provider event-verify endpoints are exempt: probes
 * must never be throttled, and webhook bursts carry their own bearer auth.
 */
export function createRateLimitMiddleware(
  config: RateLimitConfig,
): (context: Context, next: () => Promise<void>) => Promise<Response | void> {
  const refillPerMs = config.rpm / 60_000;
  const buckets = new Map<string, Bucket>();

  return async (context: Context, next: () => Promise<void>) => {
    if (config.rpm <= 0 || EXEMPT_PATH.test(context.req.path)) {
      await next();
      return;
    }
    const key = bucketKey(context);
    const timestamp = Date.now();

    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { tokens: config.burst, updatedAt: timestamp };
      buckets.set(key, bucket);
      if (buckets.size > MAX_BUCKETS) {
        for (const [k, b] of buckets) {
          if (timestamp - b.updatedAt > IDLE_SWEEP_MS) buckets.delete(k);
        }
        if (buckets.size > MAX_BUCKETS) {
          const excess = buckets.size - MAX_BUCKETS;
          const oldest = [...buckets.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt).slice(0, excess);
          for (const [k] of oldest) buckets.delete(k);
        }
      }
    }
    bucket.tokens = Math.min(config.burst, bucket.tokens + Math.max(0, timestamp - bucket.updatedAt) * refillPerMs);
    bucket.updatedAt = timestamp;

    if (bucket.tokens < 1) {
      const retryAfter = Math.max(1, Math.ceil((1 - bucket.tokens) / refillPerMs / 1000));
      context.header("retry-after", String(retryAfter));
      if (context.req.path.startsWith("/v1")) {
        return writeRuntimeFailure(context, {
          status: 429,
          errorCode: "rate_limited",
          message: "Rate limit exceeded; retry after the indicated delay.",
          meta: {},
        });
      }
      return jsonError(context, 429, "rate_limited", "Rate limit exceeded; retry after the indicated delay.");
    }
    bucket.tokens -= 1;
    await next();
  };
}

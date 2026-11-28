import type { Context } from "hono";

import { readRuntimeGrant, readTenantId } from "./auth.ts";
import { jsonError } from "./http-utils.ts";

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

/**
 * Token bucket per `(tenant_id, token_id)` on the runtime execution surface.
 * In-memory and instance-local by design: buckets reset on restart and are
 * not shared across replicas — the limit is a DoS guard, not an accounting
 * boundary.
 */
export function createRateLimitMiddleware(
  config: RateLimitConfig,
): (context: Context, next: () => Promise<void>) => Promise<Response | void> {
  const refillPerMs = config.rpm / 60_000;
  const buckets = new Map<string, Bucket>();
  const now = () => Date.now();

  return async (context: Context, next: () => Promise<void>) => {
    if (config.rpm <= 0) {
      await next();
      return;
    }
    const tenant = readTenantId(context);
    const tokenId = readRuntimeGrant(context)?.tokenId ?? "anonymous";
    const key = `${tenant}\n${tokenId}`;
    const timestamp = now();

    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { tokens: config.burst, updatedAt: timestamp };
      buckets.set(key, bucket);
      if (buckets.size > MAX_BUCKETS) {
        for (const [k, b] of buckets) {
          if (timestamp - b.updatedAt > IDLE_SWEEP_MS) buckets.delete(k);
        }
        if (buckets.size > MAX_BUCKETS) buckets.clear();
      }
    }
    bucket.tokens = Math.min(config.burst, bucket.tokens + (timestamp - bucket.updatedAt) * refillPerMs);
    bucket.updatedAt = timestamp;

    if (bucket.tokens < 1) {
      const retryAfter = Math.max(1, Math.ceil((1 - bucket.tokens) / refillPerMs / 1000));
      context.header("retry-after", String(retryAfter));
      return jsonError(context, 429, "rate_limited", "Rate limit exceeded; retry after the indicated delay.");
    }
    bucket.tokens -= 1;
    await next();
  };
}

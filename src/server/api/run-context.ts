import type { RuntimeGrant } from "../storage/runtime-token-service.ts";

export interface RunAuditContext {
  runId?: string;
  traceId?: string;
}

/** Match the 32-hex trace-id segment of a W3C `traceparent` header. */
const TRACEPARENT_PATTERN = /^[\da-f]{2}-([\da-f]{32})-[\da-f]{16}-[\da-f]{2}$/;

function randomTraceId(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

/**
 * Audit correlation for one execution request: `runId` groups every action of a caller run
 * (inherited from the grant envelope, or the `x-oc-run-id` fallback header), and `traceId`
 * carries the W3C trace context (`traceparent`), generated when the caller did not send one.
 */
export function readRunAuditContext(headers: Headers, grant?: RuntimeGrant): RunAuditContext {
  const headerRunId = headers.get("x-oc-run-id")?.trim();
  const runId = grant?.runId ?? (headerRunId && headerRunId.length <= 128 ? headerRunId : undefined);
  const traceparent = headers.get("traceparent")?.toLowerCase();
  const traceId = traceparent ? (TRACEPARENT_PATTERN.exec(traceparent)?.[1] ?? randomTraceId()) : randomTraceId();
  return { runId, traceId };
}

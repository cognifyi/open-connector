import type { PolicyRules, TokenPolicy } from "../../core/action-policy.ts";
import type { TokenAudience } from "../storage/runtime-token-service.ts";
import type { JsonRequestBody } from "./http-utils.ts";

import { Buffer } from "node:buffer";
import { requiredStringArray } from "../../core/cast.ts";
import { HttpRequestError } from "./http-utils.ts";

export const policyRequestMaxBytes: number = 256 * 1024;
export const policyRuleMaxBytes: number = 256;
export const policyRuleListMaxItems: number = 128;

export function readRuntimePolicyRules(body: JsonRequestBody): PolicyRules {
  return {
    allowedActions: readRules(body.allowedActions, "allowedActions", "action"),
    blockedActions: readRules(body.blockedActions, "blockedActions", "action"),
    allowedProxies: readRules(body.allowedProxies, "allowedProxies", "proxy"),
    blockedProxies: readRules(body.blockedProxies, "blockedProxies", "proxy"),
    allowedTriggers: readRules(body.allowedTriggers, "allowedTriggers", "action", true),
    blockedTriggers: readRules(body.blockedTriggers, "blockedTriggers", "action", true),
  };
}

export function readTokenPolicy(body: JsonRequestBody, allowOmitted = false): TokenPolicy {
  if (body.blockedTriggers !== undefined) {
    throw invalidInput("Token policy does not support Trigger block rules.");
  }
  if (body.blockedProxies !== undefined) {
    throw invalidInput("Token policy does not support proxy block rules.");
  }
  return {
    allowedActions: readRules(body.allowedActions, "allowedActions", "action", allowOmitted),
    blockedActions: readRules(body.blockedActions, "blockedActions", "action", allowOmitted),
    allowedProxies: readRules(body.allowedProxies, "allowedProxies", "proxy", allowOmitted),
    allowedTriggers: readRules(body.allowedTriggers, "allowedTriggers", "action", true),
    allowedConnections: readConnectionIds(body.allowedConnections, "allowedConnections", allowOmitted),
  };
}

const AUDIENCE_TYPES = new Set(["agent", "run", "service", "session"]);
export const RUN_ID_PATTERN: RegExp = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;

/** Optional grant-envelope fields accepted by `POST /api/runtime-tokens`. */
export function readTokenEnvelope(body: JsonRequestBody): {
  expiresAt?: string;
  runId?: string;
  audience?: TokenAudience;
} {
  let expiresAt: string | undefined;
  if (body.expiresAt !== undefined) {
    if (
      typeof body.expiresAt !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(body.expiresAt) ||
      Number.isNaN(Date.parse(body.expiresAt))
    ) {
      throw invalidInput("expiresAt must be an ISO-8601 instant string.");
    }
    expiresAt = new Date(body.expiresAt).toISOString();
  }
  let runId: string | undefined;
  if (body.runId !== undefined) {
    if (typeof body.runId !== "string" || !RUN_ID_PATTERN.test(body.runId)) {
      throw invalidInput("runId must be 1-128 chars of [a-zA-Z0-9._-], starting alphanumeric.");
    }
    runId = body.runId;
  }
  let audience: TokenAudience | undefined;
  if (body.audience !== undefined) {
    const value = body.audience;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw invalidInput("audience must be an object {type, id, onBehalfOf?}.");
    }
    const { type, id, onBehalfOf } = value as Record<string, unknown>;
    if (typeof type !== "string" || !AUDIENCE_TYPES.has(type)) {
      throw invalidInput("audience.type must be one of agent|run|service|session.");
    }
    if (typeof id !== "string" || id.length === 0 || id.length > 256) {
      throw invalidInput("audience.id must be a non-empty string up to 256 chars.");
    }
    if (
      onBehalfOf !== undefined &&
      (typeof onBehalfOf !== "string" || onBehalfOf.length === 0 || onBehalfOf.length > 256)
    ) {
      throw invalidInput("audience.onBehalfOf must be a string up to 256 chars.");
    }
    audience = { type: type as TokenAudience["type"], id, ...(onBehalfOf === undefined ? {} : { onBehalfOf }) };
  }
  return { expiresAt, runId, audience };
}

function readRules(value: unknown, fieldName: string, kind: "action" | "proxy", allowOmitted = false): string[] {
  if (value === undefined && allowOmitted) {
    return [];
  }
  const values = requiredStringArray(value, fieldName, invalidInput);
  const rules: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const rule = value.trim();
    if (!rule) {
      throw invalidInput(`${fieldName} must not contain empty rules.`);
    }
    if (Buffer.byteLength(rule, "utf8") > policyRuleMaxBytes) {
      throw invalidInput(`${fieldName} rules must not exceed ${policyRuleMaxBytes} UTF-8 bytes.`);
    }
    assertRuleSyntax(rule, fieldName, kind);
    if (!seen.has(rule)) {
      seen.add(rule);
      rules.push(rule);
    }
  }
  if (rules.length > policyRuleListMaxItems) {
    throw invalidInput(`${fieldName} must not contain more than ${policyRuleListMaxItems} rules.`);
  }
  return rules;
}

function readConnectionIds(value: unknown, fieldName: string, allowOmitted = false): string[] {
  if (value === undefined && allowOmitted) {
    return [];
  }
  const values = requiredStringArray(value, fieldName, invalidInput);
  const connectionIds: string[] = [];
  const seen = new Set<string>();
  for (const item of values) {
    const connectionId = item.trim();
    if (!connectionId) {
      throw invalidInput(`${fieldName} must not contain empty connection IDs.`);
    }
    if (Buffer.byteLength(connectionId, "utf8") > policyRuleMaxBytes) {
      throw invalidInput(`${fieldName} IDs must not exceed ${policyRuleMaxBytes} UTF-8 bytes.`);
    }
    if (!seen.has(connectionId)) {
      seen.add(connectionId);
      connectionIds.push(connectionId);
    }
  }
  if (connectionIds.length > policyRuleListMaxItems) {
    throw invalidInput(`${fieldName} must not contain more than ${policyRuleListMaxItems} rules.`);
  }
  return connectionIds;
}

function assertRuleSyntax(rule: string, fieldName: string, kind: "action" | "proxy"): void {
  if (rule === "*") {
    return;
  }
  if (kind === "proxy") {
    if (rule.includes("*") || /\s/.test(rule)) {
      throw invalidInput(`${fieldName} contains an invalid proxy rule: ${rule}.`);
    }
    return;
  }
  if (/^[^\s.*]+\.\*$/.test(rule)) {
    return;
  }
  const separator = rule.indexOf(".");
  if (rule.includes("*") || /\s/.test(rule) || separator <= 0 || separator === rule.length - 1) {
    throw invalidInput(`${fieldName} contains an invalid action rule: ${rule}.`);
  }
}

function invalidInput(message: string): HttpRequestError {
  return new HttpRequestError("invalid_input", message);
}

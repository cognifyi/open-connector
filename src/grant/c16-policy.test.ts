import type { C16Grant } from "./c16-policy.ts";

import { describe, expect, it } from "vitest";
import { ActionPolicyService, emptyPolicyRules } from "../core/action-policy.ts";
import { C16PolicyError, compileC16GrantPolicy } from "./c16-policy.ts";

const NOW = Date.parse("2026-11-28T00:00:00.000Z");
const FUTURE = "2026-11-28T00:15:00.000Z";
const PAST = "2026-11-27T23:45:00.000Z";

function grant(overrides: Partial<C16Grant> = {}): C16Grant {
  return {
    grantId: "grt_7777777777777777",
    connectionId: "con_6666666666666666",
    audienceType: "run",
    audienceId: "run_dddddddddddddddd",
    runId: "run_dddddddddddddddd",
    scopes: ["read"],
    onBehalfOf: "user_stage",
    expiresAt: FUTURE,
    epoch: 1,
    issuedAt: "2026-11-28T00:00:00.000Z",
    status: "active",
    ...overrides,
  };
}

function compile(input: C16Grant, overrides = {}) {
  return compileC16GrantPolicy(input, { toolkit: "github", tenantId: "org_acme", now: NOW, ...overrides });
}

describe("c16 grant validation", () => {
  it("rejects an expired grant", () => {
    expect(() => compile(grant({ expiresAt: PAST }))).toThrow(C16PolicyError);
  });

  it("rejects an unparseable expiresAt", () => {
    expect(() => compile(grant({ expiresAt: "not-a-date" }))).toThrow(C16PolicyError);
  });

  it("rejects revoked, used, and expired statuses", () => {
    for (const status of ["revoked", "used", "expired"]) {
      expect(() => compile(grant({ status })), status).toThrow(C16PolicyError);
    }
  });

  it("treats a missing status as active", () => {
    const input = grant();
    delete input.status;
    const { policy } = compile(input);
    expect(policy.allowedConnections).toEqual(["con_6666666666666666"]);
  });

  it("rejects empty and non-array scopes", () => {
    expect(() => compile(grant({ scopes: [] }))).toThrow(C16PolicyError);
    expect(() => compile(grant({ scopes: "read" as unknown as string[] }))).toThrow(C16PolicyError);
  });

  it("rejects scopes with whitespace and non-string entries", () => {
    expect(() => compile(grant({ scopes: ["github.* evil"] }))).toThrow(C16PolicyError);
    expect(() => compile(grant({ scopes: [42] as unknown as string[] }))).toThrow(C16PolicyError);
  });

  it("rejects another service's scope in a toolkit-bound grant", () => {
    expect(() => compile(grant({ scopes: ["notion.search"] }))).toThrow(C16PolicyError);
  });

  it("rejects unsupported oc: namespaces but keeps oc:actions:", () => {
    expect(() => compile(grant({ scopes: ["oc:connections:con-1"] }))).toThrow(C16PolicyError);
    expect(() => compile(grant({ scopes: ["oc:proxies:github"] }))).toThrow(C16PolicyError);
    const { policy } = compile(grant({ scopes: ["oc:actions:github.*"] }));
    expect(policy.allowedActions).toEqual(["github.*"]);
  });

  it("rejects malformed oc:actions patterns", () => {
    for (const scopes of [["oc:actions:"], ["oc:actions:foo*"], ["oc:actions:no-dot-here*"]]) {
      expect(() => compile(grant({ scopes })), scopes[0]).toThrow(C16PolicyError);
    }
  });

  it("rejects a zero or non-integer epoch", () => {
    expect(() => compile(grant({ epoch: 0 }))).toThrow(C16PolicyError);
    expect(() => compile(grant({ epoch: 1.5 }))).toThrow(C16PolicyError);
  });

  it("rejects empty grant, run, connection, audience, and sponsor ids", () => {
    const cases: Array<[string, Partial<C16Grant>]> = [
      ["grantId", { grantId: "  " }],
      ["runId", { runId: "  " }],
      ["connectionId", { connectionId: "  " }],
      ["audienceId", { audienceId: "  " }],
      ["onBehalfOf", { onBehalfOf: "  " }],
    ];
    for (const [field, override] of cases) {
      expect(() => compile({ ...grant(), ...override }), field).toThrow(C16PolicyError);
    }
  });

  it("rejects an unknown audience type", () => {
    expect(() => compile(grant({ audienceType: "user" as unknown as "run" }))).toThrow(C16PolicyError);
  });

  it("rejects an invalid toolkit and an invalid tenant", () => {
    expect(() => compileC16GrantPolicy(grant(), { toolkit: "git hub", tenantId: "org_acme", now: NOW })).toThrow(
      C16PolicyError,
    );
    expect(() => compileC16GrantPolicy(grant(), { toolkit: "", tenantId: "org_acme", now: NOW })).toThrow(
      C16PolicyError,
    );
    expect(() => compileC16GrantPolicy(grant(), { toolkit: "github", tenantId: "all", now: NOW })).toThrow(
      expect.any(Error),
    );
  });

  it("reports stable error codes", () => {
    try {
      compile(grant({ expiresAt: PAST }));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(C16PolicyError);
      expect((error as C16PolicyError).code).toBe("grant_expired");
    }
  });
});

describe("c16 scope mapping", () => {
  it("expands a wildcard to the toolkit wildcard, never global", () => {
    expect(compile(grant({ scopes: ["*"] })).policy.allowedActions).toEqual(["github.*"]);
  });

  it("expands coarse verbs to the toolkit wildcard", () => {
    for (const verb of ["read", "write", "admin"]) {
      expect(compile(grant({ scopes: [verb] })).policy.allowedActions, verb).toEqual(["github.*"]);
    }
  });

  it("namespaces provider-style scopes to the toolkit", () => {
    expect(compile(grant({ scopes: ["repo:read"] })).policy.allowedActions).toEqual(["github.repo:read"]);
  });

  it("passes toolkit-prefixed actions through verbatim", () => {
    const { policy } = compile(grant({ scopes: ["github.repos_list", "github.*"] }));
    expect(policy.allowedActions).toEqual(["github.repos_list", "github.*"]);
  });

  it("compiles oc:actions: scopes by stripping the prefix", () => {
    const { policy } = compile(
      grant({ scopes: ["oc:actions:github.repos_list", "oc:actions:*", "oc:actions:hackernews.get_top_stories"] }),
      { toolkit: "github" },
    );
    expect(policy.allowedActions).toEqual(["github.repos_list", "*", "hackernews.get_top_stories"]);
  });

  it("dedupes repeated scopes and keeps order", () => {
    const { policy } = compile(grant({ scopes: ["read", "github.*", "read", "*"] }));
    expect(policy.allowedActions).toEqual(["github.*"]);
  });

  it("binds the Hub connection id by default", () => {
    expect(compile(grant()).policy.allowedConnections).toEqual(["con_6666666666666666"]);
  });

  it("binds an explicit OC-side connection ref when the ids differ", () => {
    const { policy } = compile(grant(), { connectionRef: "conn-123" });
    expect(policy.allowedConnections).toEqual(["conn-123"]);
  });

  it("maps the audience into the mint envelope", () => {
    const { envelope } = compile(
      grant({ audienceType: "service", audienceId: "svc_indexer", onBehalfOf: "space_docs" }),
    );
    expect(envelope.audience).toEqual({ type: "service", id: "svc_indexer", onBehalfOf: "space_docs" });
    expect(envelope.runId).toBe("run_dddddddddddddddd");
  });

  it("normalizes tenant ids through tenant grammar", () => {
    expect(compile(grant(), { tenantId: " Org_Acme " }).tenantId).toBe("org_acme");
  });

  it("canonicalizes expiresAt to a comparable ISO instant", () => {
    const { envelope } = compile(grant({ expiresAt: "2026-11-28T00:15:00+00:00" }));
    expect(envelope.expiresAt).toBe("2026-11-28T00:15:00.000Z");
  });

  it("emits an explicit deny-by-default policy shape", () => {
    const { policy } = compile(grant());
    expect(policy.blockedActions).toEqual([]);
    expect(policy.allowedProxies).toEqual([]);
    expect(policy.allowedActions.length).toBeGreaterThan(0);
  });
});

describe("compiled policy enforcement", () => {
  it("allows a toolkit action and denies another service's action", () => {
    const { policy } = compile(grant({ scopes: ["read"] }));
    const service = new ActionPolicyService({ requireExplicitPolicy: true });
    const snapshot = service.createSnapshot(emptyPolicyRules(), policy);
    expect(snapshot.evaluate({ id: "github.repos_list" })).toMatchObject({ allowed: true });
    const denied = snapshot.evaluate({ id: "notion.search" });
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) {
      expect(denied.code).toBe("action_not_allowed");
    }
  });

  it("denies the bound connection when a different one is selected", () => {
    const { policy } = compile(grant(), { connectionRef: "conn-123" });
    const service = new ActionPolicyService({ requireExplicitPolicy: true });
    const snapshot = service.createSnapshot(emptyPolicyRules(), policy);
    expect(snapshot.evaluateConnection("conn-123").allowed).toBe(true);
    const denied = snapshot.evaluateConnection("conn-999");
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) {
      expect(denied.code).toBe("connection_not_allowed");
    }
  });

  it("keeps OC-native scopes narrow: github.* never matches notion", () => {
    const { policy } = compile(grant({ scopes: ["oc:actions:github.*"] }));
    const service = new ActionPolicyService({ requireExplicitPolicy: true });
    const snapshot = service.createSnapshot(emptyPolicyRules(), policy);
    expect(snapshot.evaluate({ id: "github.issues_create" }).allowed).toBe(true);
    expect(snapshot.evaluate({ id: "notion.search" }).allowed).toBe(false);
  });
});

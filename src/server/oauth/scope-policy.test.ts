import { describe, expect, it } from "vitest";
import { compileOAuthScopePolicy, ScopePolicyError } from "./scope-policy.ts";

describe("compileOAuthScopePolicy", () => {
  it("leaves every allow-list empty when no oc: scopes are granted", () => {
    expect(compileOAuthScopePolicy(["openid", "profile", "offline_access"])).toEqual({
      allowedActions: [],
      blockedActions: [],
      allowedProxies: [],
      allowedConnections: [],
      allowedTriggers: [],
    });
  });

  it("compiles action, connection and proxy scopes into the token policy", () => {
    const policy = compileOAuthScopePolicy([
      "oc:actions:github.*",
      "oc:actions:hackernews.get_top_stories",
      "oc:connections:conn-123",
      "oc:proxies:slack",
    ]);
    expect(policy.allowedActions).toEqual(["github.*", "hackernews.get_top_stories"]);
    expect(policy.allowedConnections).toEqual(["conn-123"]);
    expect(policy.allowedProxies).toEqual(["slack"]);
  });

  it("accepts wildcards for actions, connections and proxies", () => {
    const policy = compileOAuthScopePolicy(["oc:actions:*", "oc:connections:*", "oc:proxies:*"]);
    expect(policy.allowedActions).toEqual(["*"]);
    expect(policy.allowedConnections).toEqual(["*"]);
    expect(policy.allowedProxies).toEqual(["*"]);
  });

  it.each([
    "oc:actions:",
    "oc:actions:foo*",
    "oc:actions:*foo",
    "oc:actions:no-dot-here*",
    "oc:connections:",
    "oc:connections:a b",
    "oc:proxies:",
    "oc:proxies:svc*",
    "oc:unknown:value",
  ])("rejects malformed connector scope %s", (scope) => {
    expect(() => compileOAuthScopePolicy([scope])).toThrow(ScopePolicyError);
  });
});

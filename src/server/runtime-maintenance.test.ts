import { describe, expect, it } from "vitest";
import { RuntimeMaintenance } from "./runtime-maintenance.ts";
import { SqliteRuntimeDatabase } from "./storage/sqlite/runtime-store.ts";

function tokenRecord(id: string, expiresAt?: string) {
  return {
    id,
    name: id,
    tenantId: "local",
    tokenHash: `${id}-hash`,
    allowedActions: [] as string[],
    blockedActions: [] as string[],
    allowedProxies: [] as string[],
    allowedConnections: [] as string[],
    allowedTriggers: [] as string[],
    createdAt: new Date().toISOString(),
    expiresAt,
  };
}

describe("RuntimeMaintenance", () => {
  it("deletes expired runtime tokens across tenants and leaves live ones", async () => {
    const database = new SqliteRuntimeDatabase(":memory:");
    const instance = database.forInstance();
    const alpha = database.forTenant("alpha");

    await instance.runtimeTokenStore.add(tokenRecord("local-live"));
    await instance.runtimeTokenStore.add(tokenRecord("local-expired", "2000-01-01T00:00:00.000Z"));
    await alpha.runtimeTokenStore.add(tokenRecord("alpha-expired", "2000-01-01T00:00:00.000Z"));
    await alpha.runtimeTokenStore.add(tokenRecord("alpha-live"));

    const maintenance = new RuntimeMaintenance({ tokens: instance.runtimeTokenStore });
    await maintenance.run();

    expect(await instance.runtimeTokenStore.findById("local-live")).toBeDefined();
    expect(await instance.runtimeTokenStore.findById("local-expired")).toBeUndefined();
    expect(await instance.runtimeTokenStore.findById("alpha-expired")).toBeUndefined();
    expect(await instance.runtimeTokenStore.findById("alpha-live")).toBeDefined();
    database.close();
  });

  it("sweeps expired oauth codes and tokens through the same instance view", async () => {
    const database = new SqliteRuntimeDatabase(":memory:");
    const instance = database.forInstance();
    const nowMs = Date.now();
    await instance.oauthCodeStore.add({
      tenantId: "local",
      codeHash: "expired-code",
      clientId: "client",
      redirectUri: "https://app.example.com/callback",
      scope: "read",
      runtimeTokenId: "grant",
      issuedAt: new Date().toISOString(),
      expiresAt: nowMs - 1,
    });
    await instance.oauthTokenStore.add({
      tenantId: "local",
      tokenHash: "expired-access",
      clientId: "client",
      runtimeTokenId: "grant",
      scope: "read",
      issuedAt: new Date().toISOString(),
      expiresAt: nowMs - 1,
    });
    await instance.oauthTokenStore.add({
      tenantId: "local",
      tokenHash: "live-access",
      clientId: "client",
      runtimeTokenId: "grant",
      scope: "read",
      issuedAt: new Date().toISOString(),
      expiresAt: nowMs + 60_000,
    });

    const maintenance = new RuntimeMaintenance({
      tokens: instance.runtimeTokenStore,
      oauthTokens: instance.oauthTokenStore,
      oauthCodes: instance.oauthCodeStore,
    });
    await maintenance.run();

    expect(await instance.oauthCodeStore.consume("expired-code")).toBeUndefined();
    expect(await instance.oauthTokenStore.findByAccessTokenHash("expired-access")).toBeUndefined();
    expect(await instance.oauthTokenStore.findByAccessTokenHash("live-access")).toBeDefined();
    database.close();
  });

  it("is idempotent across runs", async () => {
    const database = new SqliteRuntimeDatabase(":memory:");
    const instance = database.forInstance();
    await instance.runtimeTokenStore.add(tokenRecord("expired", "2000-01-01T00:00:00.000Z"));
    const maintenance = new RuntimeMaintenance({ tokens: instance.runtimeTokenStore });
    await maintenance.run();
    await maintenance.run();
    expect(await instance.runtimeTokenStore.list()).toHaveLength(0);
    database.close();
  });
});

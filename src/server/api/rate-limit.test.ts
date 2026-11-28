import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createRateLimitMiddleware } from "./rate-limit.ts";

function appWith(config: { rpm: number; burst: number }): Hono {
  const app = new Hono();
  app.use("/v1/*", createRateLimitMiddleware(config));
  app.get("/v1/ping", (context) => context.json({ ok: true }));
  app.get("/other", (context) => context.json({ ok: true }));
  return app;
}

describe("rate limit middleware", () => {
  it("allows bursts up to capacity then returns 429 with Retry-After", async () => {
    const app = appWith({ rpm: 60, burst: 3 });
    for (let i = 0; i < 3; i++) {
      expect((await app.request("/v1/ping")).status).toBe(200);
    }
    const limited = await app.request("/v1/ping");
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(await limited.json()).toMatchObject({ error: { code: "rate_limited" } });
  });

  it("does not throttle other paths or a disabled limit", async () => {
    const app = appWith({ rpm: 60, burst: 1 });
    expect((await app.request("/v1/ping")).status).toBe(200);
    expect((await app.request("/v1/ping")).status).toBe(429);
    expect((await app.request("/other")).status).toBe(200);

    const disabled = appWith({ rpm: 0, burst: 1 });
    for (let i = 0; i < 5; i++) {
      expect((await disabled.request("/v1/ping")).status).toBe(200);
    }
  });

  it("refills tokens over time", async () => {
    const app = appWith({ rpm: 6000, burst: 1 });
    expect((await app.request("/v1/ping")).status).toBe(200);
    expect((await app.request("/v1/ping")).status).toBe(429);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect((await app.request("/v1/ping")).status).toBe(200);
  });
});

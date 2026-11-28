import { describe, expect, it } from "vitest";
import { createWorkerSecretCodec } from "./worker-secret-codec.ts";

describe("worker secret codecs", () => {
  it("round-trips encrypted payloads with a worker-specific prefix", async () => {
    const codec = await createWorkerSecretCodec("test-key");
    const stored = await codec.encode("secret");

    expect(stored).toMatch(/^enc:worker:v1:/);
    expect(stored).not.toContain("secret");
    await expect(codec.decode(stored)).resolves.toBe("secret");
  });

  it("fails fast without a key unless plaintext is explicitly allowed", async () => {
    await expect(createWorkerSecretCodec(undefined)).rejects.toThrow("OOMOL_CONNECT_ENCRYPTION_KEY");

    const codec = await createWorkerSecretCodec(undefined, true);
    await expect(codec.encode("value")).resolves.toBe("value");
    await expect(codec.decode("value")).resolves.toBe("value");
  });
});

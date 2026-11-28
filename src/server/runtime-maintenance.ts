import type { RuntimeExecutionOptions } from "../core/runtime-execution.ts";
import type { RuntimeLogger } from "../core/types.ts";
import type { IOAuthCodeStore, IOAuthTokenStore } from "./storage/oauth-as-stores.ts";
import type { IRuntimeTokenStore } from "./storage/runtime-token-service.ts";

import { withRuntimeExecution } from "../core/runtime-execution.ts";

export interface RuntimeMaintenanceOptions extends RuntimeExecutionOptions {
  /** Instance-scope store: the sweep deletes every tenant's expired grants. */
  tokens: IRuntimeTokenStore;
  oauthTokens?: IOAuthTokenStore;
  oauthCodes?: IOAuthCodeStore;
  logger?: RuntimeLogger;
}

/**
 * Periodic grant hygiene: expired runtime tokens and expired OAuth AS
 * codes/tokens are deleted so the backing tables do not grow without bound.
 * Authentication stays correct between sweeps because `resolveToken` already
 * rejects expired grants at read time — the sweep is the persistence-level
 * fallback, not the enforcement path.
 */
export class RuntimeMaintenance {
  private readonly options: RuntimeMaintenanceOptions;
  private readonly shutdown = new AbortController();
  private pending?: Promise<void>;
  private timer?: ReturnType<typeof setTimeout>;
  private started = false;

  constructor(options: RuntimeMaintenanceOptions) {
    this.options = options;
  }

  run(): Promise<void> {
    if (this.shutdown.signal.aborted) return Promise.resolve();
    this.pending ??= withRuntimeExecution(this.options, { operation: "runtime" }, () => this.runBatch())
      .catch((error) => {
        this.options.logger?.warn(
          { errorCode: "runtime_maintenance_failed", error: String(error) },
          "Runtime maintenance sweep failed; expired rows are retained",
        );
      })
      .finally(() => {
        this.pending = undefined;
      });
    return this.pending;
  }

  /** Node owns this timer; Workers invoke run from their scheduled entry point instead. */
  start(): void {
    if (this.started || this.shutdown.signal.aborted) return;
    this.started = true;
    const tick = (): void => {
      void this.run().finally(() => {
        if (this.shutdown.signal.aborted) return;
        this.timer = setTimeout(tick, 60_000);
        this.timer.unref?.();
      });
    };
    tick();
  }

  async close(): Promise<void> {
    this.shutdown.abort();
    clearTimeout(this.timer);
    await this.pending;
  }

  private async runBatch(): Promise<void> {
    const deleted = await this.options.tokens.deleteExpired(new Date().toISOString());
    if (deleted > 0) {
      this.options.logger?.info({ deleted }, "expired runtime tokens deleted");
    }
    const nowMs = Date.now();
    await this.options.oauthTokens?.deleteExpired(nowMs);
    await this.options.oauthCodes?.deleteExpired(nowMs);
  }
}

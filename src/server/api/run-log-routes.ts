import type { ActionRunner } from "../actions/action-runner.ts";
import type { RunLogCaller, RunLogListInput } from "../storage/runtime-store.ts";
import type { ScopedServices } from "../tenant-services.ts";
import type { Context } from "hono";

import { Hono } from "hono";
import { optionalString } from "../../core/cast.ts";
import { decodeRunLogCursor } from "../storage/runtime-store.ts";
import { readTenantId } from "./auth.ts";
import { HttpRequestError, jsonError } from "./http-utils.ts";

export interface RunLogRoutesOptions {
  services: ScopedServices;
}

type RunLogListQuery =
  | {
      ok: true;
      input: RunLogListInput;
    }
  | {
      ok: false;
      message: string;
    };

function isRunLogCaller(value: string): value is RunLogCaller {
  return value === "http" || value === "mcp" || value === "web";
}

function readRunLogListInput(context: Context): RunLogListQuery {
  const rawLimit = optionalString(context.req.query("limit"));
  const limit = rawLimit === undefined ? 50 : Number(rawLimit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    return { ok: false, message: "limit must be an integer between 1 and 100." };
  }

  const cursor = optionalString(context.req.query("cursor"));
  if (cursor !== undefined) {
    try {
      decodeRunLogCursor(cursor);
    } catch {
      return { ok: false, message: "cursor is invalid." };
    }
  }

  const input: RunLogListInput = { limit };
  if (cursor !== undefined) {
    input.cursor = cursor;
  }
  const service = optionalString(context.req.query("service"));
  if (service !== undefined) {
    input.service = service;
  }
  const actionId = optionalString(context.req.query("actionId"));
  if (actionId !== undefined) {
    if (actionId.length > 256) {
      return { ok: false, message: "actionId must be at most 256 characters." };
    }
    input.actionId = actionId;
  }
  const caller = optionalString(context.req.query("caller"));
  if (caller !== undefined) {
    if (!isRunLogCaller(caller)) {
      return { ok: false, message: "caller must be one of http, mcp, or web." };
    }
    input.caller = caller;
  }
  const ok = optionalString(context.req.query("ok"));
  if (ok !== undefined) {
    if (ok !== "true" && ok !== "false") {
      return { ok: false, message: "ok must be true or false." };
    }
    input.ok = ok === "true";
  }
  const since = optionalString(context.req.query("since"));
  if (since !== undefined) {
    if (Number.isNaN(Date.parse(since))) {
      return { ok: false, message: "since must be an ISO-8601 timestamp." };
    }
    input.since = new Date(since).toISOString();
  }

  return { ok: true, input };
}

/** Action execution run log query and inspection routes. */
export function createRunLogRoutes({ services }: RunLogRoutesOptions): Hono {
  const app = new Hono();
  const scoped = async (context: Context): Promise<ActionRunner> => {
    const { actions } = await services.forTenant(readTenantId(context));
    if (!actions) throw new HttpRequestError("service_unavailable", "Action runs are unavailable.", 503);
    return actions;
  };

  app.get("/runs", async (context) => {
    const query = readRunLogListInput(context);
    if (!query.ok) {
      return jsonError(context, 400, "invalid_input", query.message);
    }

    return context.json(await (await scoped(context)).listRuns(query.input));
  });

  app.get("/runs/export", async (context) => {
    const query = readRunLogListInput(context);
    if (!query.ok) {
      return jsonError(context, 400, "invalid_input", query.message);
    }
    const page = await (await scoped(context)).listRuns(query.input);
    const body = page.items.map((run) => JSON.stringify(run)).join("\n") + (page.items.length > 0 ? "\n" : "");
    context.header("content-type", "application/x-ndjson; charset=utf-8");
    if (page.nextCursor !== undefined) {
      context.header("x-next-cursor", page.nextCursor);
    }
    return context.body(body);
  });

  app.get("/runs/:id", async (context) => {
    const id = context.req.param("id");
    const run = await (await scoped(context)).getRun(id);
    return run ? context.json(run) : jsonError(context, 404, "run_not_found", `Run not found: ${id}.`);
  });

  return app;
}

/**
 * Compile granted OAuth scopes into the runtime token policy they authorize.
 *
 * Scope grammar (aligned with the C16 grant contract):
 *   oc:actions:<pattern>       — `*`, `<service>.*`, or `<service>.<action>`
 *   oc:connections:<id|*>      — one connection id or `*` for any connection
 *   oc:proxies:<service|*>     — one proxy service name or `*`
 *
 * Scopes outside the `oc:` namespace (openid, profile, offline_access, the
 * MCP access scope, …) carry no connector policy and are ignored. An absent
 * `oc:` family leaves its allow-list empty, which keeps the deployment's
 * default semantics: open under the classic policy, deny-all under
 * `OOMOL_CONNECT_REQUIRE_EXPLICIT_POLICY`.
 */

export class ScopePolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopePolicyError";
  }
}

export interface CompiledScopePolicy {
  allowedActions: string[];
  blockedActions: string[];
  allowedProxies: string[];
  allowedConnections: string[];
  allowedTriggers: string[];
}

const ACTION_SCOPE = /^oc:actions:(.+)$/;
const CONNECTION_SCOPE = /^oc:connections:(.+)$/;
const PROXY_SCOPE = /^oc:proxies:(.+)$/;
const OC_SCOPE = /^oc:/;
const ACTION_ID_PATTERN = /^[^\s.*]+\.[^\s]+$/;
const SERVICE_PATTERN = /^[^\s,*]+$/;

function assertActionPattern(pattern: string): void {
  if (pattern === "*" || /^[^\s.*]+\.\*$/.test(pattern) || ACTION_ID_PATTERN.test(pattern)) {
    return;
  }
  throw new ScopePolicyError(`Invalid oc:actions scope pattern: ${pattern}.`);
}

/** True when `scope` is a well-formed `oc:` connector scope. */
export function isConnectorScope(scope: string): boolean {
  if (!scope.startsWith("oc:")) return false;
  try {
    compileOAuthScopePolicy([scope]);
    return true;
  } catch {
    return false;
  }
}

export function compileOAuthScopePolicy(scopes: readonly string[]): CompiledScopePolicy {
  const policy: CompiledScopePolicy = {
    allowedActions: [],
    blockedActions: [],
    allowedProxies: [],
    allowedConnections: [],
    allowedTriggers: [],
  };
  for (const scope of scopes) {
    const action = ACTION_SCOPE.exec(scope);
    if (action) {
      assertActionPattern(action[1]);
      policy.allowedActions.push(action[1]);
      continue;
    }
    const connection = CONNECTION_SCOPE.exec(scope);
    if (connection) {
      const id = connection[1];
      if (id !== "*" && !SERVICE_PATTERN.test(id)) {
        throw new ScopePolicyError(`Invalid oc:connections scope value: ${id}.`);
      }
      policy.allowedConnections.push(id);
      continue;
    }
    const proxy = PROXY_SCOPE.exec(scope);
    if (proxy) {
      const service = proxy[1];
      if (service !== "*" && (!SERVICE_PATTERN.test(service) || service.includes("*"))) {
        throw new ScopePolicyError(`Invalid oc:proxies scope value: ${service}.`);
      }
      policy.allowedProxies.push(service);
      continue;
    }
    if (OC_SCOPE.test(scope)) {
      throw new ScopePolicyError(`Unsupported connector scope: ${scope}.`);
    }
  }
  return policy;
}

/**
 * Error with a stable code suitable for HTTP responses, raised by tenant
 * resolution and tenant-scope checks. Route handlers map `code` to a status.
 */
export class TenantError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

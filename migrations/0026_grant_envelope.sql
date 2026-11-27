-- OC-2a: runtime tokens become run-scoped grant envelopes.
-- `expires_at` is an ISO-8601 instant checked at resolve time; `run_id` binds
-- the grant to an Omni run for audit joins; `audience_json` carries the C16
-- audience object {type, id, onBehalfOf?}.
alter table runtime_tokens add column expires_at text;
alter table runtime_tokens add column run_id text;
alter table runtime_tokens add column audience_json text;
create index runtime_tokens_expires_idx on runtime_tokens (tenant_id, expires_at);

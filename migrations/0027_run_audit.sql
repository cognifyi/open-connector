alter table runs add column run_id text;
alter table runs add column trace_id text;
alter table runs add column grant_id text;
alter table runs add column connection_id text;
create index runs_tenant_started_at_id_idx on runs (tenant_id, started_at desc, id desc);

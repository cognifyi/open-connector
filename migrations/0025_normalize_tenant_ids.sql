-- OC-1f: tenant_id is normalized to lowercase at the request boundary, so any
-- row persisted with a mixed-case id before the normalization landed would be
-- orphaned by tenant-scoped reads. Lower every stored id; a case-insensitive
-- collision surfaces as a primary-key violation instead of silent merging.
update connections set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update connection_requests set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update connection_retirements set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update custom_mcp set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update idempotency_records set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update oauth_authorization_codes set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update oauth_client_configs set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update oauth_states set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update oauth_tokens set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update provider_preferences set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update runs set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update runtime_tokens set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update saas_cleanup set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update trigger_source_applications set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);
update trigger_subscriptions set tenant_id = lower(tenant_id) where tenant_id <> lower(tenant_id);

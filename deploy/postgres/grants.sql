-- Run with psql as the migration owner after schema.sql.
-- Supply existing, separately provisioned role names:
-- psql --set=runtime_role=kms_runtime --set=observer_role=kms_observer -f grants.sql
-- Each national KMS uses a dedicated database and runtime role.
GRANT USAGE ON SCHEMA kms_meta, kms_secret, kms_audit TO :"runtime_role";
GRANT SELECT, INSERT, UPDATE ON kms_meta.state, kms_secret.state TO :"runtime_role";
GRANT INSERT ON kms_audit.events TO :"runtime_role";
GRANT USAGE ON ALL SEQUENCES IN SCHEMA kms_audit TO :"runtime_role";
GRANT USAGE ON SCHEMA kms_meta, kms_audit TO :"observer_role";
GRANT SELECT ON kms_meta.state, kms_audit.events TO :"observer_role";
-- Neither runtime nor observer owns schemas/tables or receives DELETE/TRUNCATE,
-- CREATE, audit UPDATE, superuser, BYPASSRLS, or owner-role membership.

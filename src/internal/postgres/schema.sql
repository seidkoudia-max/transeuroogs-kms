-- Apply once with a dedicated migration/owner identity, never the runtime role.
CREATE SCHEMA IF NOT EXISTS kms_meta;
CREATE SCHEMA IF NOT EXISTS kms_secret;
CREATE SCHEMA IF NOT EXISTS kms_audit;
CREATE TABLE IF NOT EXISTS kms_meta.state (
    namespace text PRIMARY KEY,
    generation text NOT NULL,
    version bigint NOT NULL CHECK (version >= 0),
    metadata jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS kms_secret.state (
    namespace text PRIMARY KEY REFERENCES kms_meta.state(namespace),
    ciphertext bytea NOT NULL
);
CREATE TABLE IF NOT EXISTS kms_audit.events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    namespace text NOT NULL,
    request_id text NOT NULL,
    actor text NOT NULL,
    operation text NOT NULL,
    phase text NOT NULL,
    status integer NOT NULL,
    version bigint NOT NULL
);
REVOKE ALL ON SCHEMA kms_meta, kms_secret, kms_audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA kms_meta, kms_secret, kms_audit FROM PUBLIC;

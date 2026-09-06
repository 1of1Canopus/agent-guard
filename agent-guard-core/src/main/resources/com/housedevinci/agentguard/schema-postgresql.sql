-- Agent Guard schema (PostgreSQL). Idempotent: safe to run at every startup.

CREATE TABLE IF NOT EXISTS agentguard_decision (
  id               uuid PRIMARY KEY,
  principal_id     varchar(255) NOT NULL,
  principal_roles  text NOT NULL DEFAULT '',
  principal_scopes text NOT NULL DEFAULT '',
  tenant_id        varchar(255),
  tool             varchar(255) NOT NULL,
  side_effect      varchar(16)  NOT NULL,
  arguments_json   text NOT NULL,
  args_hash        char(64) NOT NULL,
  args_preview     text NOT NULL DEFAULT '',
  conversation_id  varchar(255),
  correlation_id   varchar(255),
  created_at       timestamptz NOT NULL,
  expires_at       timestamptz NOT NULL,
  state            varchar(16) NOT NULL,
  decided_by       varchar(255),
  decided_at       timestamptz,
  executed         boolean NOT NULL DEFAULT false,
  result_json      text
);
CREATE INDEX IF NOT EXISTS agentguard_decision_lookup
  ON agentguard_decision (principal_id, tool, args_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS agentguard_decision_state
  ON agentguard_decision (state, created_at);

CREATE TABLE IF NOT EXISTS agentguard_audit (
  seq            bigserial PRIMARY KEY,
  ts             timestamptz NOT NULL,
  principal_id   varchar(255) NOT NULL,
  tenant_id      varchar(255),
  tool           varchar(255) NOT NULL,
  args_hash      char(64) NOT NULL,
  result_hash    varchar(64) NOT NULL DEFAULT '',
  latency_ms     bigint NOT NULL DEFAULT 0,
  decision       varchar(24) NOT NULL,
  correlation_id varchar(255) NOT NULL DEFAULT '',
  decision_id    varchar(64),
  prev_hash      char(64) NOT NULL,
  hash           char(64) NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS agentguard_audit_principal ON agentguard_audit (principal_id, ts);
CREATE INDEX IF NOT EXISTS agentguard_audit_tool ON agentguard_audit (tool, ts);

-- Append-only: any UPDATE or DELETE is refused at the database level.
CREATE OR REPLACE FUNCTION agentguard_audit_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'agentguard_audit is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS agentguard_audit_append_only ON agentguard_audit;
CREATE TRIGGER agentguard_audit_append_only
  BEFORE UPDATE OR DELETE ON agentguard_audit
  FOR EACH ROW EXECUTE FUNCTION agentguard_audit_append_only();

CREATE TABLE IF NOT EXISTS agentguard_budget (
  key        varchar(512) PRIMARY KEY,
  used       bigint NOT NULL,
  expires_at timestamptz NOT NULL
);

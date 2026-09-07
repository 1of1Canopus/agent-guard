-- Agent Guard schema (PostgreSQL). Idempotent, and serialised against the audit sink's appends and
-- against other instances starting at the same time: the whole script runs in one transaction under
-- the sink's advisory lock (see JdbcSupport.initializeSchema).
SELECT pg_advisory_xact_lock(18374244850549833);

CREATE TABLE IF NOT EXISTS agentguard_decision (
  id               uuid PRIMARY KEY,
  principal_id     varchar(255) NOT NULL,
  principal_roles  text NOT NULL DEFAULT '',
  principal_scopes text NOT NULL DEFAULT '',
  tenant_id        varchar(255),
  tool             varchar(255) NOT NULL,
  side_effect      varchar(16)  NOT NULL,
  arguments_json   text NOT NULL,
  args_hash        varchar(64) NOT NULL,
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
CREATE INDEX IF NOT EXISTS agentguard_decision_lookup2
  ON agentguard_decision (principal_id, tenant_id, tool, args_hash, created_at DESC);
DROP INDEX IF EXISTS agentguard_decision_lookup;
CREATE INDEX IF NOT EXISTS agentguard_decision_pending
  ON agentguard_decision (principal_id) WHERE state = 'PENDING';
CREATE INDEX IF NOT EXISTS agentguard_decision_state
  ON agentguard_decision (state, created_at);

CREATE TABLE IF NOT EXISTS agentguard_audit (
  seq            bigserial PRIMARY KEY,
  ts             timestamptz NOT NULL,
  principal_id   varchar(255) NOT NULL,
  tenant_id      varchar(255),
  tool           varchar(255) NOT NULL,
  args_hash      varchar(64) NOT NULL,
  result_hash    varchar(64) NOT NULL DEFAULT '',
  latency_ms     bigint NOT NULL DEFAULT 0,
  decision       varchar(24) NOT NULL,
  correlation_id varchar(255) NOT NULL DEFAULT '',
  decision_id    varchar(64),
  actor_id       varchar(255),
  prev_hash      char(64) NOT NULL,
  hash           char(64) NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS agentguard_audit_principal ON agentguard_audit (principal_id, ts);
CREATE INDEX IF NOT EXISTS agentguard_audit_tool ON agentguard_audit (tool, ts);

ALTER TABLE agentguard_audit ADD COLUMN IF NOT EXISTS actor_id varchar(255);

-- Chain version each row was written with (C6): backfilled 'ag1' for rows that predate this
-- column, so enabling agentguard.audit.hmac-secret on a running installation does not make the
-- pre-key trail report BROKEN; the verifier applies the function each row actually recorded.
ALTER TABLE agentguard_audit ADD COLUMN IF NOT EXISTS chain_version varchar(8) NOT NULL DEFAULT 'ag1';

-- Key id each row was signed with (keyed-from-birth, QUESTIONS.md #20): part of the hashed material
-- itself, from row 1, so key rotation is data (a new id, a new secret), not a chain-format change.
-- 'none' for unkeyed rows (AuditChain.UNKEYED_KEY_ID); backfilled 'k1' for keyed rows written before
-- this column existed (AuditChain.keyed(byte[])'s historical default id), 'none' for unkeyed ones.
ALTER TABLE agentguard_audit ADD COLUMN IF NOT EXISTS key_id varchar(64);
UPDATE agentguard_audit SET key_id = CASE WHEN chain_version = 'ag2h' THEN 'k1' ELSE 'none' END
  WHERE key_id IS NULL;
ALTER TABLE agentguard_audit ALTER COLUMN key_id SET NOT NULL;

-- Append-only: UPDATE, DELETE and TRUNCATE are refused at the database level. A role that owns the
-- table can still DISABLE TRIGGER: run the application with a role that has INSERT/SELECT only
-- (see docs, "Database roles"); the anchor below makes tail deletion and truncation detectable.
CREATE OR REPLACE FUNCTION agentguard_audit_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'agentguard_audit is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'agentguard_audit_append_only') THEN
    CREATE TRIGGER agentguard_audit_append_only
      BEFORE UPDATE OR DELETE ON agentguard_audit
      FOR EACH ROW EXECUTE FUNCTION agentguard_audit_append_only();
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'agentguard_audit_no_truncate') THEN
    CREATE TRIGGER agentguard_audit_no_truncate
      BEFORE TRUNCATE ON agentguard_audit
      FOR EACH STATEMENT EXECUTE FUNCTION agentguard_audit_append_only();
  END IF;
END $$;

-- Chain anchor: head hash + row count, written in the same transaction as every append.
CREATE TABLE IF NOT EXISTS agentguard_audit_anchor (
  id         smallint PRIMARY KEY CHECK (id = 1),
  head_hash  char(64) NOT NULL,
  row_count  bigint NOT NULL,
  updated_at timestamptz NOT NULL
);

-- Design change: keyed-from-birth (QUESTIONS.md #20, the maintainers's ruling). A trail is keyed from row 1
-- or unkeyed forever; there is no mixing and no later switch. `keyed` is the external,
-- attacker-unwritable record of which one this trail is: set once, at the first append, and
-- immutable afterwards (the monotonic trigger below). A row's own chain_version is not enough on
-- its own (it is part of what a table-owning attacker rewrites); `keyed` is what the verifier
-- checks every row's chain_version against. Replaces the earlier `keyed_from_seq` column (a
-- sequence position, dropped below): with no mixing allowed there is nothing left to locate.
ALTER TABLE agentguard_audit_anchor DROP COLUMN IF EXISTS keyed_from_seq;
ALTER TABLE agentguard_audit_anchor ADD COLUMN IF NOT EXISTS keyed boolean;
-- Backfill an existing anchor row from the trail it anchors (an installation upgrading from
-- before this column existed): the trail's own head says whether it was ever written keyed.
UPDATE agentguard_audit_anchor a SET keyed = COALESCE(
    (SELECT t.chain_version = 'ag2h' FROM agentguard_audit t ORDER BY t.seq DESC LIMIT 1),
    false)
  WHERE a.id = 1 AND a.keyed IS NULL;

-- The anchor only moves forward, one row at a time: a runtime role with UPDATE on it cannot reset
-- it after trimming the trail (the owner can drop the trigger; documented residual). `keyed` may be
-- set exactly once (at the row's creation, alongside the first head_hash/row_count) and never
-- change afterwards, so a runtime-role attacker who downgrades or wholesale-rewrites the trail
-- cannot also flip the record of which mode this trail legitimately started in.
CREATE OR REPLACE FUNCTION agentguard_audit_anchor_monotonic() RETURNS trigger AS $$
BEGIN
  IF NEW.row_count <> OLD.row_count + 1 OR NEW.head_hash = OLD.head_hash THEN
    RAISE EXCEPTION 'agentguard_audit_anchor only advances by one row (attempted % -> %)',
      OLD.row_count, NEW.row_count;
  END IF;
  IF NEW.keyed IS DISTINCT FROM OLD.keyed THEN
    RAISE EXCEPTION 'agentguard_audit_anchor.keyed is immutable once set (attempted % -> %)',
      OLD.keyed, NEW.keyed;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'agentguard_audit_anchor_monotonic') THEN
    CREATE TRIGGER agentguard_audit_anchor_monotonic
      BEFORE UPDATE ON agentguard_audit_anchor
      FOR EACH ROW EXECUTE FUNCTION agentguard_audit_anchor_monotonic();
  END IF;
END $$;

-- Append-only, mirroring agentguard_audit: nothing refuses DELETE/TRUNCATE on the anchor without
-- this (the security review F3(a)) — an anchor row is only as protective as it is hard to lose, and losing it
-- silently reopened the exact V2/whole-trail-downgrade attack the anchor exists to close.
CREATE OR REPLACE FUNCTION agentguard_audit_anchor_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'agentguard_audit_anchor is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'agentguard_audit_anchor_no_delete') THEN
    CREATE TRIGGER agentguard_audit_anchor_no_delete
      BEFORE DELETE ON agentguard_audit_anchor
      FOR EACH ROW EXECUTE FUNCTION agentguard_audit_anchor_append_only();
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'agentguard_audit_anchor_no_truncate') THEN
    CREATE TRIGGER agentguard_audit_anchor_no_truncate
      BEFORE TRUNCATE ON agentguard_audit_anchor
      FOR EACH STATEMENT EXECUTE FUNCTION agentguard_audit_anchor_append_only();
  END IF;
END $$;

-- Amendment (the maintainers, after the security review's design review): the schema step never seeds an anchor row from
-- an existing, non-empty trail — deriving `keyed` (or, before it, `keyed_from_seq`) from row data
-- is exactly the guess the anchor exists to make unnecessary. If a trail already has rows and no
-- anchor, `JdbcAuditSink` refuses to append (AG-AUDIT-002) rather than silently re-anchoring: see
-- "Audit chain keying" in docs/index.md for the operator remedy (start a new trail). For a genuinely
-- empty trail there is nothing to seed either way — the first real append creates the anchor row.

ALTER TABLE agentguard_audit_anchor ALTER COLUMN keyed SET NOT NULL;

ALTER TABLE IF EXISTS agentguard_budget ALTER COLUMN key TYPE text;

CREATE TABLE IF NOT EXISTS agentguard_budget (
  key        text PRIMARY KEY,
  used       bigint NOT NULL,
  expires_at timestamptz NOT NULL
);

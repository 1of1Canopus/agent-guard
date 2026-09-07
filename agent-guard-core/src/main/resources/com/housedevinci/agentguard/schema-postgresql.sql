-- Agent Guard schema (PostgreSQL). Idempotent, and serialised against the audit sink's appends and
-- against other instances starting at the same time: the whole script runs in one transaction under
-- the sink's advisory lock (see JdbcSupport.initializeSchema).
SELECT pg_advisory_xact_lock(18374244850549833);

-- Keyed-from-birth (QUESTIONS.md #20) declares agentguard_audit.key_id and
-- agentguard_audit_anchor.keyed NOT NULL in the CREATE TABLE bodies below, with no backfill: this
-- branch is unreleased, so there is no upgrade path from a database written by an earlier build.
-- A pre-redesign agentguard_audit (append-only trigger already installed, no key_id column) or a
-- pre-redesign anchor (no keyed column) is refused here, with a clear message, rather than left to
-- fail later on the append-only trigger, the anchor's monotonic trigger, or a missing-column error
-- from an INSERT.
-- J1 (Cipher): resolved search_path-relative via to_regclass, the same way every other statement in
-- this step resolves the table, instead of scanning information_schema across every schema the role
-- can see. A pre-redesign copy sitting in another visible schema (e.g. after an operator followed
-- docs/index.md's "rename or drop" and did `ALTER TABLE ... SET SCHEMA archive`) no longer blocks a
-- fresh install in the current schema.
-- K1 (Cipher): to_regclass resolves like a *reference* — the first schema on the search_path that
-- holds the name, anywhere along the path — while the unqualified CREATE TABLE below targets only
-- current_schema(), the first *existing* entry. A pre-redesign copy in a schema that is on the
-- search_path but behind the creation schema was therefore visible to to_regclass and refused a
-- fresh install that would have been entirely correct. Both oids are now resolved against
-- current_schema() explicitly, quote_ident'd so a schema named with capitals or a dot is not
-- re-parsed as a different name, matching exactly what the unqualified CREATE TABLE targets.
DO $$
DECLARE
  a oid := to_regclass(quote_ident(current_schema()) || '.agentguard_audit');
  n oid := to_regclass(quote_ident(current_schema()) || '.agentguard_audit_anchor');
BEGIN
  IF (a IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = a AND attname = 'key_id' AND attnum > 0 AND NOT attisdropped))
     OR (n IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = n AND attname = 'keyed' AND attnum > 0 AND NOT attisdropped)) THEN
    RAISE EXCEPTION
      'audit schema predates keyed-from-birth; archive the table and start a new trail (see SECURITY-NOTES)';
  END IF;
END $$;

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
  key_id         varchar(64) NOT NULL,
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
-- 'none' for unkeyed rows (AuditChain.UNKEYED_KEY_ID). Declared NOT NULL in the CREATE TABLE body
-- above: this branch is unreleased, so there is no earlier row to backfill (see the schema-predates
-- guard above for a database that has one anyway).

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
  updated_at timestamptz NOT NULL,
  keyed      boolean NOT NULL
);

-- Design change: keyed-from-birth (QUESTIONS.md #20, Dollar's ruling). A trail is keyed from row 1
-- or unkeyed forever; there is no mixing and no later switch. `keyed` is the external,
-- attacker-unwritable record of which one this trail is: set once, at the first append, and
-- immutable afterwards (the monotonic trigger below). A row's own chain_version is not enough on
-- its own (it is part of what a table-owning attacker rewrites); `keyed` is what the verifier
-- checks every row's chain_version against. Replaces the earlier `keyed_from_seq` column (a
-- sequence position, dropped below): with no mixing allowed there is nothing left to locate.
-- Kept as a courtesy for an owner cleaning up by hand; inert on a database that never had it.
ALTER TABLE agentguard_audit_anchor DROP COLUMN IF EXISTS keyed_from_seq;
-- `keyed` is declared NOT NULL in the CREATE TABLE body above, with no backfill: this branch is
-- unreleased, so there is no earlier anchor row to derive it from, and deriving it from row data
-- (chain_version) is exactly the re-derivation path this design removed. A database with an
-- existing agentguard_audit but no key_id column — including one whose anchor predates `keyed` —
-- is refused by the schema-predates guard above before this table is ever reached.

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
-- this (Cipher F3(a)) — an anchor row is only as protective as it is hard to lose, and losing it
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

-- Amendment (Dollar, after Cipher's design review): the schema step never seeds an anchor row from
-- an existing, non-empty trail — deriving `keyed` (or, before it, `keyed_from_seq`) from row data
-- is exactly the guess the anchor exists to make unnecessary. If a trail already has rows and no
-- anchor, `JdbcAuditSink` refuses to append (AG-AUDIT-002) rather than silently re-anchoring: see
-- "Audit chain keying" in docs/index.md for the operator remedy (start a new trail). For a genuinely
-- empty trail there is nothing to seed either way — the first real append creates the anchor row.

ALTER TABLE IF EXISTS agentguard_budget ALTER COLUMN key TYPE text;

CREATE TABLE IF NOT EXISTS agentguard_budget (
  key        text PRIMARY KEY,
  used       bigint NOT NULL,
  expires_at timestamptz NOT NULL
);

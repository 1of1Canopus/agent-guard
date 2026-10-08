package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, PR 34 (fix/schema-trigger-guards), pass 1. {@code probe_*} tests fail on the
 * reviewed head and name a finding; {@code confirm_*} tests pin a behaviour the review measured and
 * accepted (a control that holds, a claim of the PR that holds, or a stated residual).
 */
@Testcontainers
class CipherProbePr34JdbcTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static final AtomicInteger SEQ = new AtomicInteger();
  private static final String PW = "probe-runtime";

  private static String freshDatabase() throws SQLException {
    String db = "cp34_" + SEQ.incrementAndGet();
    exec("test", "CREATE DATABASE " + db);
    exec(db, "REVOKE CREATE ON SCHEMA public FROM PUBLIC");
    return db;
  }

  private static String url(String db) {
    return "jdbc:postgresql://"
        + POSTGRES.getHost()
        + ":"
        + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
        + "/"
        + db;
  }

  private static void exec(String db, String... statements) throws SQLException {
    as(db, POSTGRES.getUsername(), POSTGRES.getPassword(), statements);
  }

  private static void as(String db, String user, String pw, String... statements)
      throws SQLException {
    try (Connection c = DriverManager.getConnection(url(db), user, pw);
        Statement st = c.createStatement()) {
      for (String s : statements) {
        st.execute(s);
      }
    }
  }

  private static String query(String db, String sql) throws SQLException {
    try (Connection c =
            DriverManager.getConnection(url(db), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      rs.next();
      return rs.getString(1);
    }
  }

  private static DataSource ds(String db, String user, String pw, String currentSchema) {
    var ds = new PGSimpleDataSource();
    ds.setUrl(url(db) + (currentSchema == null ? "" : "?currentSchema=" + currentSchema));
    ds.setUser(user);
    ds.setPassword(pw);
    return ds;
  }

  private static DataSource owner(String db) {
    return ds(db, POSTGRES.getUsername(), POSTGRES.getPassword(), null);
  }

  private static String runtimeRole(String db) throws SQLException {
    String role = "rt_" + db;
    exec(
        db,
        "CREATE ROLE " + role + " LOGIN PASSWORD '" + PW + "'",
        "GRANT SELECT, INSERT ON agentguard_audit TO " + role,
        "GRANT USAGE ON SEQUENCE agentguard_audit_seq_seq TO " + role,
        "GRANT SELECT, INSERT, UPDATE ON agentguard_decision, agentguard_audit_anchor TO " + role,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON agentguard_budget TO " + role);
    return role;
  }

  private static String resource(String path) {
    try (InputStream in = CipherProbePr34JdbcTest.class.getResourceAsStream(path)) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final String SCRIPT_012 = "/com/housedevinci/agentguard/schema-postgresql.sql";
  private static final String SCRIPT_011 =
      "/com/housedevinci/agentguard/schema-postgresql-0.1.1.sql";

  private static String guarded() throws SQLException {
    String db = freshDatabase();
    JdbcSupport.initializeSchema(owner(db));
    assertThatCode(() -> JdbcSupport.verifyGuards(owner(db))).doesNotThrowAnyException();
    return db;
  }

  private static AgentGuardException refusal(DataSource ds) {
    Throwable t = catchThrowable(() -> JdbcSupport.verifyGuards(ds));
    assertThat(t).isInstanceOf(AgentGuardException.class);
    return (AgentGuardException) t;
  }

  // ---- trigger states named in the brief ------------------------------------------------------

  @Test
  void confirm_one_missing_trigger_is_refused() throws Exception {
    String db = guarded();
    exec(db, "DROP TRIGGER agentguard_audit_no_truncate ON agentguard_audit");
    var e = refusal(owner(db));
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage()).contains("agentguard_audit_no_truncate", "is missing");
  }

  @Test
  void confirm_one_disabled_trigger_is_refused() throws Exception {
    String db = guarded();
    exec(
        db,
        "ALTER TABLE agentguard_audit_anchor DISABLE TRIGGER agentguard_audit_anchor_no_delete");
    assertThat(
            query(
                db,
                "SELECT tgenabled FROM pg_trigger WHERE tgname = 'agentguard_audit_anchor_no_delete'"))
        .isEqualTo("D");
    var e = refusal(owner(db));
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage()).contains("tgenabled=D");
  }

  @Test
  void confirm_same_named_trigger_on_a_different_function_is_refused() throws Exception {
    String db = guarded();
    exec(
        db,
        "CREATE FUNCTION public.ag_noop() RETURNS trigger AS $$ BEGIN RETURN OLD; END; $$ LANGUAGE plpgsql",
        "DROP TRIGGER agentguard_audit_append_only ON agentguard_audit",
        "CREATE TRIGGER agentguard_audit_append_only BEFORE UPDATE OR DELETE ON agentguard_audit"
            + " FOR EACH ROW EXECUTE FUNCTION public.ag_noop()",
        "ALTER TABLE agentguard_audit ENABLE ALWAYS TRIGGER agentguard_audit_append_only");
    var e = refusal(owner(db));
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage()).contains("points at function public.ag_noop");
    // and the same function NAME in another schema, same shape, no-op body
    exec(
        db,
        "CREATE SCHEMA evil",
        "CREATE FUNCTION evil.agentguard_audit_append_only() RETURNS trigger AS $$ BEGIN RETURN OLD; END; $$ LANGUAGE plpgsql",
        "DROP TRIGGER agentguard_audit_append_only ON agentguard_audit",
        "CREATE TRIGGER agentguard_audit_append_only BEFORE UPDATE OR DELETE ON agentguard_audit"
            + " FOR EACH ROW EXECUTE FUNCTION evil.agentguard_audit_append_only()",
        "ALTER TABLE agentguard_audit ENABLE ALWAYS TRIGGER agentguard_audit_append_only");
    assertThat(refusal(owner(db)).getMessage())
        .contains("points at function evil.agentguard_audit_append_only");
  }

  @Test
  void confirm_partitioned_trail_is_refused_through_its_partition() throws Exception {
    String db = guarded();
    exec(
        db,
        "CREATE SCHEMA old",
        "ALTER TABLE agentguard_audit SET SCHEMA old",
        // the bundled shape cannot be partitioned as is (PK on seq and UNIQUE on hash need the
        // partition key); a table owner can still build one without the UNIQUE
        "CREATE TABLE agentguard_audit (LIKE old.agentguard_audit INCLUDING DEFAULTS) PARTITION BY RANGE (seq)",
        "CREATE TABLE agentguard_audit_p1 PARTITION OF agentguard_audit FOR VALUES FROM (MINVALUE) TO (MAXVALUE)",
        "CREATE TRIGGER agentguard_audit_append_only BEFORE UPDATE OR DELETE ON agentguard_audit"
            + " FOR EACH ROW EXECUTE FUNCTION agentguard_audit_append_only()",
        "CREATE TRIGGER agentguard_audit_no_truncate BEFORE TRUNCATE ON agentguard_audit"
            + " FOR EACH STATEMENT EXECUTE FUNCTION agentguard_audit_append_only()",
        "ALTER TABLE agentguard_audit ENABLE ALWAYS TRIGGER agentguard_audit_append_only",
        "ALTER TABLE agentguard_audit ENABLE ALWAYS TRIGGER agentguard_audit_no_truncate");
    var e = refusal(owner(db));
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage()).contains("inheritance edge", "agentguard_audit_p1");
  }

  @Test
  void confirm_second_schema_with_the_same_names_is_judged_by_current_schema_only()
      throws Exception {
    String db = freshDatabase();
    // public: the 0.1.1 archive-remedy state (unguarded live pair)
    exec(db, "BEGIN", resource(SCRIPT_011), "COMMIT");
    exec(
        db,
        "CREATE SCHEMA archive",
        "ALTER TABLE agentguard_audit SET SCHEMA archive",
        "ALTER TABLE agentguard_audit_anchor SET SCHEMA archive",
        "BEGIN",
        resource(SCRIPT_011),
        "COMMIT",
        "CREATE SCHEMA s2");
    // s2: a fully guarded 0.1.2 pair under the same names
    JdbcSupport.initializeSchema(ds(db, POSTGRES.getUsername(), POSTGRES.getPassword(), "s2"));
    assertThatCode(
            () ->
                JdbcSupport.verifyGuards(
                    ds(db, POSTGRES.getUsername(), POSTGRES.getPassword(), "s2")))
        .doesNotThrowAnyException();
    assertThat(refusal(owner(db)).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    // a guarded s2 after the unguarded public on the path does not rescue public
    assertThat(refusal(ds(db, POSTGRES.getUsername(), POSTGRES.getPassword(), "public,s2")).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  // ---- findings -------------------------------------------------------------------------------

  /**
   * CP34-2: an UNLOGGED trail and anchor pass the census. PostgreSQL truncates an unlogged table on
   * crash recovery without firing any trigger, and does not replicate it to a standby, so both the
   * trail and the anchor vanish together and the next boot starts a fresh chain at GENESIS.
   */
  @Test
  void probe_unlogged_trail_and_anchor_pass_the_guard_check() throws Exception {
    String db = guarded();
    exec(
        db,
        "ALTER TABLE agentguard_audit SET UNLOGGED",
        "ALTER TABLE agentguard_audit_anchor SET UNLOGGED");
    assertThat(
            query(
                db,
                "SELECT string_agg(relpersistence::text, '' ORDER BY relname) FROM pg_class"
                    + " WHERE relname IN ('agentguard_audit', 'agentguard_audit_anchor')"))
        .isEqualTo("uu");
    Throwable t = catchThrowable(() -> JdbcSupport.verifyGuards(owner(db)));
    assertThat(t)
        .as(
            "an UNLOGGED trail is emptied by crash recovery with no trigger firing; must be refused")
        .isInstanceOf(AgentGuardException.class);
  }

  /**
   * CP34-2, the consequence: a backend crash empties both tables, no trigger fires, nothing is
   * refused.
   */
  @Test
  void confirm_unlogged_trail_and_anchor_are_emptied_by_crash_recovery() throws Exception {
    String db = guarded();
    exec(
        db,
        "ALTER TABLE agentguard_audit SET UNLOGGED",
        "ALTER TABLE agentguard_audit_anchor SET UNLOGGED",
        "INSERT INTO agentguard_audit (ts, principal_id, tool, args_hash, decision, key_id,"
            + " prev_hash, hash) VALUES (now(), 'p', 't', 'a', 'ALLOW', 'none', repeat('0',64),"
            + " repeat('1',64))",
        "INSERT INTO agentguard_audit_anchor VALUES (1, repeat('1',64), 1, now(), false)",
        "CHECKPOINT");
    String pid = query(db, "SELECT pg_backend_pid()");
    try (Connection victim =
            DriverManager.getConnection(url(db), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = victim.createStatement();
        ResultSet rs = st.executeQuery("SELECT pg_backend_pid()")) {
      rs.next();
      var r = POSTGRES.execInContainer("kill", "-9", rs.getString(1));
      assertThat(r.getExitCode()).isZero();
    }
    String rows = null;
    for (int i = 0; i < 60 && rows == null; i++) {
      try {
        rows =
            query(
                db,
                "SELECT (SELECT count(*) FROM agentguard_audit) || '/'"
                    + " || (SELECT count(*) FROM agentguard_audit_anchor)");
      } catch (SQLException recovering) {
        Thread.sleep(500);
      }
    }
    assertThat(pid).isNotNull();
    assertThat(rows).as("trail rows / anchor rows after crash recovery").isEqualTo("0/0");
    // Fix pass: on the reviewed head the census was still clean here; with the CP34-2 fix the
    // next start refuses the unlogged pair.
    assertThat(catchThrowable(() -> JdbcSupport.verifyGuards(owner(db))))
        .isInstanceOfSatisfying(
            AgentGuardException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  /**
   * CP34-3: catalogue-derived names (trigger, rule, policy, child table, schema) are concatenated
   * into the refusal raw, so a name carrying a line break forges a log line in the startup failure.
   */
  @Test
  void probe_catalogue_names_reach_the_refusal_with_control_characters() throws Exception {
    String db = guarded();
    exec(
        db,
        "CREATE TRIGGER \"x\nagentguard: audit trail guards verified at startup\" BEFORE INSERT ON"
            + " agentguard_budget FOR EACH ROW EXECUTE FUNCTION agentguard_audit_append_only()");
    var e = refusal(owner(db));
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(e.getMessage())
        .as("no raw control character from the catalogue in the refusal")
        .doesNotContain("\n");
  }

  // ---- condition 3: the non-owner with initialize-schema=true ---------------------------------

  /**
   * The builder's claim, measured: the released 0.1.1 script, run as a non-owner on an already
   * guarded schema, fails with 42501 whether or not the role holds CREATE on the schema. 0.1.1's
   * {@code initializeSchema} ran it in one transaction and rethrew, so that configuration never
   * booted on 0.1.1.
   */
  @Test
  void confirm_011_script_as_a_non_owner_never_succeeded_on_a_guarded_schema() throws Exception {
    String db = guarded();
    String role = runtimeRole(db);
    Throwable plain =
        catchThrowable(() -> as(db, role, PW, "BEGIN", resource(SCRIPT_011), "COMMIT"));
    assertThat(plain).isInstanceOf(SQLException.class);
    assertThat(((SQLException) plain).getSQLState()).isEqualTo("42501");
    exec(db, "GRANT CREATE ON SCHEMA public TO " + role);
    Throwable withCreate =
        catchThrowable(() -> as(db, role, PW, "BEGIN", resource(SCRIPT_011), "COMMIT"));
    assertThat(withCreate).isInstanceOf(SQLException.class);
    assertThat(((SQLException) withCreate).getSQLState()).isEqualTo("42501");
    assertThat(withCreate.getMessage()).contains("must be owner");
  }

  /**
   * The alternative the PR body offers (ALTER only when tgenabled is not A) would not make the
   * non-owner boot: with the five ALTER statements removed entirely, the 0.1.2 script still fails
   * for the non-owner before reaching them.
   */
  @Test
  void confirm_conditional_alter_would_not_let_a_non_owner_boot() throws Exception {
    String db = guarded();
    String role = runtimeRole(db);
    exec(db, "GRANT CREATE ON SCHEMA public TO " + role);
    String withoutAlters =
        resource(SCRIPT_012)
            .replaceAll("(?m)^ALTER TABLE agentguard_audit\\S*\\s+ENABLE ALWAYS.*$", "");
    assertThat(withoutAlters).doesNotContain("ENABLE ALWAYS TRIGGER agentguard");
    Throwable t = catchThrowable(() -> as(db, role, PW, "BEGIN", withoutAlters, "COMMIT"));
    assertThat(t).isInstanceOf(SQLException.class);
    assertThat(((SQLException) t).getSQLState()).isEqualTo("42501");
    // and the shipped path reports it coded, guards intact
    var e =
        catchThrowable(() -> JdbcSupport.initializeSchemaAndVerifyGuards(ds(db, role, PW, null)));
    assertThat(e).isInstanceOf(AgentGuardException.class);
    assertThat(((AgentGuardException) e).code()).isEqualTo(ErrorCodes.SCHEMA_CREATION_FAILED);
    assertThat(e.getMessage()).doesNotContain("must be owner").contains("42501");
  }

  // ---- startup-only limitation ----------------------------------------------------------------

  /** Stated residual: nothing re-checks after startup; the owner disables and deletes. */
  @Test
  void confirm_owner_ddl_after_the_check_goes_unnoticed_until_next_start() throws Exception {
    String db = guarded();
    exec(
        db,
        "INSERT INTO agentguard_audit (ts, principal_id, tool, args_hash, decision, key_id,"
            + " prev_hash, hash) VALUES (now(), 'p', 't', 'a', 'ALLOW', 'none', repeat('0',64), repeat('1',64))");
    JdbcSupport.verifyGuards(owner(db));
    assertThatThrownBy(() -> exec(db, "DELETE FROM agentguard_audit"))
        .isInstanceOf(SQLException.class);
    exec(
        db,
        "ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only",
        "DELETE FROM agentguard_audit",
        "ALTER TABLE agentguard_audit ENABLE ALWAYS TRIGGER agentguard_audit_append_only");
    assertThat(query(db, "SELECT count(*) FROM agentguard_audit")).isEqualTo("0");
    // re-enabled before the next start: the next census is clean; only the anchor tells
    assertThatCode(() -> JdbcSupport.verifyGuards(owner(db))).doesNotThrowAnyException();
  }
}

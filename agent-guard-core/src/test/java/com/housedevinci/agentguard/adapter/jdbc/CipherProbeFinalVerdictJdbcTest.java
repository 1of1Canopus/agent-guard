package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** the security review final-verdict pass on 05f209d (the J1 fix). Temporary. */
@Testcontainers
class CipherProbeFinalVerdictJdbcTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  /** Plain pool: search_path is the PostgreSQL default, {@code "$user", public}. */
  static HikariDataSource ds;

  /** Same database, but every connection sees {@code archive} on the search_path, after public. */
  static HikariDataSource dsArchiveOnPath;

  @BeforeAll
  static void open() {
    ds = pool(null);
    dsArchiveOnPath = pool("SET search_path = public, archive");
  }

  private static HikariDataSource pool(String initSql) {
    var pool = new HikariDataSource();
    pool.setJdbcUrl(POSTGRES.getJdbcUrl());
    pool.setUsername(POSTGRES.getUsername());
    pool.setPassword(POSTGRES.getPassword());
    pool.setMaximumPoolSize(4);
    if (initSql != null) {
      pool.setConnectionInitSql(initSql);
    }
    return pool;
  }

  @AfterAll
  static void close() {
    ds.close();
    dsArchiveOnPath.close();
  }

  @BeforeEach
  void fresh() throws SQLException {
    sql("DROP SCHEMA IF EXISTS archive CASCADE");
    sql("DROP SCHEMA IF EXISTS oldcopy CASCADE");
    sql("DROP TABLE IF EXISTS agentguard_audit_anchor");
    sql("DROP TABLE IF EXISTS agentguard_audit");
    sql("DROP TABLE IF EXISTS agentguard_budget");
    sql("DROP TABLE IF EXISTS agentguard_decision");
  }

  /**
   * K1. The J1 fix scopes the guard to search_path <em>visibility</em> ({@code to_regclass}), but
   * {@code CREATE TABLE IF NOT EXISTS agentguard_audit} targets the <em>creation</em> schema —
   * {@code current_schema()}, the first entry of the search_path. The two are not the same set. A
   * stale pre-redesign copy in a schema that is on the search_path but <em>behind</em> the creation
   * schema is visible to {@code to_regclass} and is therefore refused, even though the step would
   * have created a brand-new, correct table in the schema ahead of it. This is J1's own symptom,
   * narrowed from "any schema the role can see" to "any schema on the search_path" rather than
   * closed. Asserted here as it behaves today (the reproduction); the fix inverts it to {@code
   * doesNotThrowAnyException}.
   */
  @Test
  void probe_a_pre_redesign_copy_behind_the_creation_schema_blocks_a_fresh_install()
      throws Exception {
    sql("CREATE SCHEMA archive");
    sql("CREATE TABLE archive.agentguard_audit (seq bigserial PRIMARY KEY, hash char(64))");
    assertThatThrownBy(() -> JdbcSupport.initializeSchema(dsArchiveOnPath))
        .hasMessageContaining("audit schema predates keyed-from-birth");
  }

  /**
   * K1, the other half: the refusal above is a false positive, not a protection. With the guard out
   * of the way the very same database installs cleanly — the new table lands in {@code public}, it
   * has {@code key_id}, and an unqualified reference resolves to it and not to the stale copy in
   * {@code archive}. Proven here by giving {@code public} a table that already satisfies the guard
   * (so the guard cannot fire) and letting the rest of the step run over the same layout.
   */
  @Test
  void confirms_a_pre_redesign_copy_behind_the_creation_schema_is_harmless_to_the_install()
      throws Exception {
    sql("CREATE SCHEMA archive");
    sql("CREATE TABLE archive.agentguard_audit (seq bigserial PRIMARY KEY, hash char(64))");
    assertThatCode(() -> JdbcSupport.initializeSchema(ds)).doesNotThrowAnyException();
    assertThat(
            query(
                "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                    + " WHERE c.relname = 'agentguard_audit' ORDER BY 1"))
        .containsExactly("archive", "public");
    assertThat(
            query(
                "SELECT attname FROM pg_attribute WHERE attrelid = 'public.agentguard_audit'::regclass"
                    + " AND attname = 'key_id' AND NOT attisdropped"))
        .containsExactly("key_id");
    assertThat(
            queryOn(dsArchiveOnPath, "SELECT to_regclass('agentguard_audit')::regclass::oid::text"))
        .isEqualTo(query("SELECT 'public.agentguard_audit'::regclass::oid::text"));
  }

  /**
   * K2 (not a finding, recorded). The guard's column test reads {@code pg_catalog.pg_attribute}. An
   * operator who has revoked the default PUBLIC grant on it turns the schema step into a startup
   * failure — but a loud one, naming the catalog table, and never a silent pass. Fails closed.
   */
  @Test
  void confirms_the_guard_fails_closed_when_the_role_cannot_read_pg_catalog() throws Exception {
    sql("DROP ROLE IF EXISTS agentguard_probe_role");
    sql("CREATE ROLE agentguard_probe_role LOGIN PASSWORD 'probe'");
    sql("GRANT USAGE, CREATE ON SCHEMA public TO agentguard_probe_role");
    sql("CREATE TABLE agentguard_audit (seq bigserial PRIMARY KEY, hash char(64))");
    sql("GRANT SELECT, INSERT ON agentguard_audit TO agentguard_probe_role");
    sql("REVOKE SELECT ON pg_attribute FROM PUBLIC");
    try (var restricted = pool(null)) {
      restricted.setUsername("agentguard_probe_role");
      restricted.setPassword("probe");
      assertThatThrownBy(() -> JdbcSupport.initializeSchema(restricted))
          .rootCause()
          .hasMessageContaining("pg_attribute");
    } finally {
      sql("GRANT SELECT ON pg_attribute TO PUBLIC");
      sql("DROP OWNED BY agentguard_probe_role");
      sql("DROP ROLE IF EXISTS agentguard_probe_role");
    }
  }

  /**
   * K3 (not a finding, recorded). A dropped-and-re-added {@code key_id} is accepted, and a column
   * that is only dropped is refused: {@code attnum > 0 AND NOT attisdropped} reads the live column
   * set, and the dropped column's own catalog row keeps a mangled name that could never match.
   */
  @Test
  void confirms_a_dropped_and_readded_key_id_column_is_read_correctly() throws Exception {
    JdbcSupport.initializeSchema(ds);
    sql("ALTER TABLE agentguard_audit DROP COLUMN key_id");
    assertThatThrownBy(() -> JdbcSupport.initializeSchema(ds))
        .hasMessageContaining("audit schema predates keyed-from-birth");
    assertThat(
            query(
                "SELECT attname FROM pg_attribute WHERE attrelid = 'agentguard_audit'::regclass"
                    + " AND attisdropped"))
        .allSatisfy(name -> assertThat(name).contains("pg.dropped"));
    sql("ALTER TABLE agentguard_audit ADD COLUMN key_id varchar(64) NOT NULL DEFAULT 'none'");
    assertThatCode(() -> JdbcSupport.initializeSchema(ds)).doesNotThrowAnyException();
  }

  /**
   * K4 (not a finding, recorded). {@code to_regclass('agentguard_audit')} folds an unquoted name to
   * lower case, exactly as the unquoted {@code CREATE TABLE} in the same script does, so a quoted
   * mixed-case table of a similar name is a different object to both and trips nothing.
   */
  @Test
  void confirms_a_quoted_mixed_case_lookalike_table_does_not_trip_the_guard() throws Exception {
    sql("CREATE TABLE \"AgentGuard_Audit\" (seq bigserial PRIMARY KEY, hash char(64))");
    try {
      assertThatCode(() -> JdbcSupport.initializeSchema(ds)).doesNotThrowAnyException();
      assertThat(query("SELECT to_regclass('agentguard_audit')::text"))
          .containsExactly("agentguard_audit");
    } finally {
      sql("DROP TABLE \"AgentGuard_Audit\"");
    }
  }

  private static void sql(String statement) throws SQLException {
    try (var c = ds.getConnection();
        Statement st = c.createStatement()) {
      st.execute(statement);
    }
  }

  private static List<String> query(String statement) throws SQLException {
    return queryOn(ds, statement);
  }

  private static List<String> queryOn(HikariDataSource pool, String statement) throws SQLException {
    var out = new ArrayList<String>();
    try (var c = pool.getConnection();
        Statement st = c.createStatement();
        var rs = st.executeQuery(statement)) {
      while (rs.next()) {
        out.add(rs.getString(1));
      }
    }
    return out;
  }
}

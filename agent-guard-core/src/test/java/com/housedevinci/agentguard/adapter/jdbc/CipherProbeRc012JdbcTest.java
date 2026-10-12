package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, release candidate 0.1.2, core side (B-RC12-2). {@code probe_*} fails on the
 * reviewed head 050b0a6.
 */
@Testcontainers
class CipherProbeRc012JdbcTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static String url(String db) {
    return "jdbc:postgresql://"
        + POSTGRES.getHost()
        + ":"
        + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
        + "/"
        + db;
  }

  private static void exec(String db, String user, String pw, String... statements)
      throws SQLException {
    try (Connection c = DriverManager.getConnection(url(db), user, pw);
        Statement st = c.createStatement()) {
      for (String s : statements) {
        st.execute(s);
      }
    }
  }

  private static String resource(String path) {
    try (InputStream in = CipherProbeRc012JdbcTest.class.getResourceAsStream(path)) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * B-RC12-2. The owner warning compares tableowner with current_user. A runtime role that is a
   * member of the owning role (the usual "app_owner / app_rw" grant layout done wrong) holds every
   * owner privilege, disables the append-only trigger, and is never warned. The read is also not
   * scoped to current_schema() and not pg_catalog-qualified, unlike the rest of the check.
   */
  @Test
  void probe_member_of_the_owner_role_can_disable_the_guard_and_is_not_warned() throws Exception {
    String su = POSTGRES.getUsername();
    String supw = POSTGRES.getPassword();
    exec(
        "test",
        su,
        supw,
        "CREATE DATABASE rc12own",
        "CREATE ROLE rc12_owner NOLOGIN",
        "CREATE ROLE rc12_rt LOGIN PASSWORD 'rc12' IN ROLE rc12_owner");
    exec(
        "rc12own",
        su,
        supw,
        "BEGIN",
        resource(GuardCensus.SCRIPT),
        "COMMIT",
        "ALTER TABLE agentguard_audit OWNER TO rc12_owner",
        "ALTER TABLE agentguard_audit_anchor OWNER TO rc12_owner");

    var rt = new PGSimpleDataSource();
    rt.setUrl(url("rc12own"));
    rt.setUser("rc12_rt");
    rt.setPassword("rc12");

    boolean warned = JdbcSupport.runtimeRoleOwnsAuditTable(rt);
    exec(
        "rc12own",
        "rc12_rt",
        "rc12",
        "ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only");

    assertThat(warned)
        .as("a role that could just disable the append-only trigger must be reported as owner")
        .isTrue();
  }

  /** B-RC12-2, second schema: a same-named table elsewhere must not answer for the current one. */
  @Test
  void owner_check_is_judged_by_the_current_schema_only() throws Exception {
    String su = POSTGRES.getUsername();
    String supw = POSTGRES.getPassword();
    exec(
        "test",
        su,
        supw,
        "CREATE DATABASE rc12schema",
        "CREATE ROLE rc12s_rt LOGIN PASSWORD 'rc12'");
    exec(
        "rc12schema",
        su,
        supw,
        "CREATE SCHEMA decoy",
        "CREATE TABLE decoy.agentguard_audit (id int)",
        "ALTER TABLE decoy.agentguard_audit OWNER TO rc12s_rt",
        "CREATE SCHEMA live",
        "CREATE TABLE live.agentguard_audit (id int)",
        "GRANT USAGE ON SCHEMA live TO rc12s_rt",
        "GRANT USAGE ON SCHEMA decoy TO rc12s_rt");
    assertThat(JdbcSupport.runtimeRoleOwnsAuditTable(schemaDs("live"))).isFalse();
    assertThat(JdbcSupport.runtimeRoleOwnsAuditTable(schemaDs("decoy"))).isTrue();
  }

  private static PGSimpleDataSource schemaDs(String schema) {
    var ds = new PGSimpleDataSource();
    ds.setUrl(url("rc12schema"));
    ds.setCurrentSchema(schema);
    ds.setUser("rc12s_rt");
    ds.setPassword("rc12");
    return ds;
  }
}

package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.jdbc.JdbcDecisionStore;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.DecisionStore;
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
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, PR 34 (fix/schema-trigger-guards), pass 1, starter side. {@code probe_*} fails
 * on the reviewed head.
 */
@Testcontainers
class CipherProbePr34StartupTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static final AtomicInteger SEQ = new AtomicInteger();

  private static String url(String db) {
    return "jdbc:postgresql://"
        + POSTGRES.getHost()
        + ":"
        + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
        + "/"
        + db;
  }

  private static void exec(String db, String... statements) throws SQLException {
    try (Connection c =
            DriverManager.getConnection(url(db), POSTGRES.getUsername(), POSTGRES.getPassword());
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

  private static String resource(String path) {
    try (InputStream in = CipherProbePr34StartupTest.class.getResourceAsStream(path)) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The 0.1.x AG-AUDIT-002 remedy state: the live pair in public carries no guard at all. */
  private static String archivedState() throws SQLException {
    String db = "cp34s_" + SEQ.incrementAndGet();
    exec("test", "CREATE DATABASE " + db);
    String s011 = resource("/com/housedevinci/agentguard/schema-postgresql-0.1.1.sql");
    exec(
        db,
        "BEGIN",
        s011,
        "COMMIT",
        "CREATE SCHEMA archive",
        "ALTER TABLE agentguard_audit SET SCHEMA archive",
        "ALTER TABLE agentguard_audit_anchor SET SCHEMA archive",
        "BEGIN",
        s011,
        "COMMIT");
    return db;
  }

  /**
   * CP34-1: an application that supplies its own DecisionStore and AuditSink (JDBC adapters on the
   * context's DataSource, a supported override: both starter beans are ConditionalOnMissingBean)
   * removes every edge that builds the lazy gate, so the census never runs and the context starts
   * on the unguarded archive-remedy schema. Design page section 3 (b) requires the gate to be
   * unconditional for exactly this case.
   */
  @Test
  void probe_user_supplied_jdbc_stores_start_on_an_unguarded_trail() throws Exception {
    String db = archivedState();
    var ds = new PGSimpleDataSource();
    ds.setUrl(url(db));
    ds.setUser(POSTGRES.getUsername());
    ds.setPassword(POSTGRES.getPassword());
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withBean(DataSource.class, () -> ds)
        .withBean(DecisionStore.class, () -> new JdbcDecisionStore(ds))
        .withBean(AuditSink.class, () -> new JdbcAuditSink(ds))
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=JDBC",
            "agentguard.budgets.store=MEMORY",
            "agentguard.jdbc.initialize-schema=false")
        .run(
            ctx -> {
              String guards =
                  query(
                      db,
                      "SELECT count(*) FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON"
                          + " c.oid = t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid ="
                          + " c.relnamespace WHERE NOT t.tgisinternal AND n.nspname = 'public'");
              assertThat(guards).as("guards on the live pair").isEqualTo("0");
              assertThat(ctx)
                  .as("a JDBC store over an unguarded trail must refuse to start (AG-SCHEMA-003)")
                  .hasFailed();
            });
  }
}

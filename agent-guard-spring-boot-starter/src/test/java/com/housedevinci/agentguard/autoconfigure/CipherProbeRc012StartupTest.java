package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditSink;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, release candidate 0.1.2, starter side (B-RC12-1). {@code probe_*} fails on the
 * reviewed head 050b0a6. The third probe is the refusal the accepted fix adds (review note of
 * 2026-10-11, "a smaller fix for B-RC12-1").
 */
@Testcontainers
class CipherProbeRc012StartupTest {

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

  private static String resource(String path) {
    try (InputStream in = CipherProbeRc012StartupTest.class.getResourceAsStream(path)) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static DataSource ds(String db) {
    var ds = new PGSimpleDataSource();
    ds.setUrl(url(db));
    ds.setUser(POSTGRES.getUsername());
    ds.setPassword(POSTGRES.getPassword());
    return ds;
  }

  /** A database whose four tables carry the five bundled guards (0.1.2 script). */
  private static String guarded() throws SQLException {
    String db = "rc12g_" + SEQ.incrementAndGet();
    exec("test", "CREATE DATABASE " + db);
    exec(db, "BEGIN", resource("/com/housedevinci/agentguard/schema-postgresql.sql"), "COMMIT");
    return db;
  }

  /** The 0.1.x AG-AUDIT-002 remedy state: the live pair in public carries no guard at all. */
  private static String archived() throws SQLException {
    String db = "rc12a_" + SEQ.incrementAndGet();
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
   * B-RC12-1, path (a). A separate audit database is a common deployment: the application keeps its
   * primary DataSource for business data and wires its own JdbcAuditSink on a second one. The gate
   * verifies the primary DataSource (ObjectProvider.getIfAvailable), logs "audit trail guards
   * verified", and the sink writes into an unguarded trail. SECURITY-NOTES and CHANGELOG claim the
   * check covers "the application supplies its own store beans".
   */
  @Test
  void probe_own_audit_sink_on_a_second_datasource_starts_on_an_unguarded_trail() throws Exception {
    DataSource primary = ds(guarded());
    DataSource audit = ds(archived());
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withBean("primaryDataSource", DataSource.class, () -> primary, bd -> bd.setPrimary(true))
        .withBean("auditDataSource", DataSource.class, () -> audit)
        .withBean(AuditSink.class, () -> new JdbcAuditSink(audit))
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=JDBC",
            "agentguard.budgets.store=MEMORY",
            "agentguard.jdbc.initialize-schema=false")
        .run(
            ctx ->
                assertThat(ctx)
                    .as(
                        "a JdbcAuditSink over an unguarded trail must refuse to start (AG-SCHEMA-003)")
                    .hasFailed());
  }

  /**
   * B-RC12-1, path (b). The gate decides from properties alone. An application that sets
   * agentguard.store=MEMORY (for example copied from the local-trial instructions) and supplies its
   * own JdbcAuditSink gets no check at all and, because its own DecisionStore replaces the
   * starter's, not even the MEMORY warning.
   */
  @Test
  void probe_own_jdbc_audit_sink_under_store_memory_is_never_checked() throws Exception {
    DataSource audit = ds(archived());
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withBean(DataSource.class, () -> audit)
        .withBean(AuditSink.class, () -> new JdbcAuditSink(audit))
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.budgets.store=MEMORY")
        .run(
            ctx ->
                assertThat(ctx)
                    .as("a JdbcAuditSink bean over an unguarded trail must refuse to start")
                    .hasFailed());
  }

  private static AgentGuardException refusal(AssertableApplicationContext ctx) {
    assertThat(ctx).hasFailed();
    Throwable t = ctx.getStartupFailure();
    while (t != null && !(t instanceof AgentGuardException)) {
      t = t.getCause();
    }
    assertThat(t).as("an AgentGuardException in the cause chain").isNotNull();
    return (AgentGuardException) t;
  }

  private static ApplicationContextRunner twoDataSources(DataSource primary, DataSource audit) {
    return new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withBean("primaryDataSource", DataSource.class, () -> primary, bd -> bd.setPrimary(true))
        .withBean("auditDataSource", DataSource.class, () -> audit)
        .withBean("auditSink", AuditSink.class, () -> new JdbcAuditSink(audit))
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=JDBC",
            "agentguard.budgets.store=MEMORY",
            "agentguard.jdbc.initialize-schema=false");
  }

  /**
   * B-RC12-1, the accepted fix. A JdbcAuditSink bean on a DataSource other than the checked one is
   * refused with AG-SCHEMA-007 naming both beans; agentguard.schema.gate.datasource names the
   * DataSource to check, and the gate then checks that one; an unknown name refuses.
   */
  @Test
  void probe_named_audit_datasource_is_the_one_checked() throws Exception {
    DataSource primary = ds(guarded());
    DataSource archivedAudit = ds(archived());
    DataSource guardedAudit = ds(guarded());

    twoDataSources(primary, guardedAudit)
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo("AG-SCHEMA-007");
              assertThat(e.getMessage())
                  .as("names the sink's DataSource and the checked one")
                  .contains("auditDataSource")
                  .contains("primaryDataSource");
            });

    twoDataSources(primary, archivedAudit)
        .withPropertyValues("agentguard.schema.gate.datasource=auditDataSource")
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo("AG-SCHEMA-003"));

    twoDataSources(primary, guardedAudit)
        .withPropertyValues("agentguard.schema.gate.datasource=auditDataSource")
        .run(ctx -> assertThat(ctx).hasNotFailed());

    twoDataSources(primary, guardedAudit)
        .withPropertyValues("agentguard.schema.gate.datasource=noSuchDataSource")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .hasMessageContaining("noSuchDataSource");
            });
  }
}

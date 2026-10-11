package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.ErrorCodes;
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
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.LazyInitializationBeanFactoryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.datasource.TransactionAwareDataSourceProxy;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * B-RC12-1: every {@code JdbcAuditSink} bean is checked against the {@code DataSource} the gate
 * verified, by identity, on each path the container offers to create one.
 */
@Testcontainers
class SchemaGateSinkCoverageTest {

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
    try (InputStream in = SchemaGateSinkCoverageTest.class.getResourceAsStream(path)) {
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

  private static DataSource guarded() throws SQLException {
    String db = "sgs_g_" + SEQ.incrementAndGet();
    exec("test", "CREATE DATABASE " + db);
    exec(db, "BEGIN", resource("/com/housedevinci/agentguard/schema-postgresql.sql"), "COMMIT");
    return ds(db);
  }

  /** The 0.1.x archive-remedy state: the live pair carries no guard. */
  private static DataSource archived() throws SQLException {
    String db = "sgs_a_" + SEQ.incrementAndGet();
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
    return ds(db);
  }

  private static ApplicationContextRunner runner(String store) {
    return new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=" + store,
            "agentguard.budgets.store=MEMORY",
            "agentguard.jdbc.initialize-schema=false");
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

  @Test
  void starter_built_sink_on_the_checked_datasource_starts() throws Exception {
    DataSource primary = guarded();
    runner("JDBC")
        .withBean(DataSource.class, () -> primary)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(JdbcAuditSink.class).dataSource()).isSameAs(primary);
            });
  }

  @Test
  void starter_stores_use_the_named_datasource() throws Exception {
    DataSource primary = guarded();
    DataSource audit = guarded();
    runner("JDBC")
        .withBean("primaryDataSource", DataSource.class, () -> primary, bd -> bd.setPrimary(true))
        .withBean("auditDataSource", DataSource.class, () -> audit)
        .withPropertyValues("agentguard.schema.gate.datasource=auditDataSource")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(JdbcAuditSink.class).dataSource()).isSameAs(audit);
              assertThat(ctx.getBean(AgentGuardSchemaGate.class).dataSource()).isSameAs(audit);
            });
  }

  @Test
  void every_sink_is_checked_not_only_the_first() throws Exception {
    DataSource primary = guarded();
    DataSource other = guarded();
    runner("JDBC")
        .withBean("primaryDataSource", DataSource.class, () -> primary, bd -> bd.setPrimary(true))
        .withBean("otherDataSource", DataSource.class, () -> other)
        .withBean(
            "aSink", AuditSink.class, () -> new JdbcAuditSink(primary), bd -> bd.setPrimary(true))
        .withBean("zSink", JdbcAuditSink.class, () -> new JdbcAuditSink(other))
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_DATASOURCE_MISMATCH);
              assertThat(e.getMessage()).contains("'zSink'").contains("otherDataSource");
            });
  }

  @Test
  void a_proxy_around_the_checked_datasource_is_refused() throws Exception {
    DataSource primary = guarded();
    runner("JDBC")
        .withBean("primaryDataSource", DataSource.class, () -> primary)
        .withBean(
            AuditSink.class, () -> new JdbcAuditSink(new TransactionAwareDataSourceProxy(primary)))
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_DATASOURCE_MISMATCH);
              assertThat(e.getMessage()).contains("not a bean").contains("identity");
            });
  }

  @Test
  void a_sink_declared_by_another_port_type_is_checked() throws Exception {
    DataSource audit = archived();
    runner("MEMORY")
        .withBean(DataSource.class, () -> audit)
        .withBean(AuditReader.class, () -> new JdbcAuditSink(audit), bd -> bd.setPrimary(true))
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  /**
   * Global lazy initialization, and a lazy sink nothing injects (the recorder takes the primary
   * in-memory sink): only the check's own eager lookup creates it, so only that lookup can refuse.
   */
  @Test
  void a_lazy_sink_nothing_injects_is_checked_at_startup() throws Exception {
    DataSource audit = archived();
    runner("MEMORY")
        .withInitializer(
            c -> c.addBeanFactoryPostProcessor(new LazyInitializationBeanFactoryPostProcessor()))
        .withBean(DataSource.class, () -> audit)
        .withBean(
            "primarySink",
            AuditSink.class,
            () -> new InMemoryAuditSink(AuditChain.unkeyed()),
            bd -> bd.setPrimary(true))
        .withBean(
            "lazySink", AuditSink.class, () -> new JdbcAuditSink(audit), bd -> bd.setLazyInit(true))
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  @Test
  void a_sink_with_no_datasource_bean_to_check_is_refused() throws Exception {
    DataSource audit = guarded();
    runner("MEMORY")
        .withBean(AuditSink.class, () -> new JdbcAuditSink(audit))
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_DATASOURCE_MISMATCH);
              assertThat(e.getMessage()).contains("no DataSource bean");
            });
  }

  @Test
  void a_guarded_sink_under_store_memory_starts() throws Exception {
    DataSource audit = guarded();
    runner("MEMORY")
        .withBean(DataSource.class, () -> audit)
        .withBean(AuditSink.class, () -> new JdbcAuditSink(audit))
        .run(ctx -> assertThat(ctx).hasNotFailed());
  }

  @Test
  void an_unknown_name_refuses_even_without_a_jdbc_store() {
    runner("MEMORY")
        .withPropertyValues("agentguard.schema.gate.datasource=missing")
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_DATASOURCE_MISMATCH);
              assertThat(e.getMessage()).contains("missing");
            });
  }

  @Test
  void a_prototype_sink_created_after_startup_is_checked_at_creation() throws Exception {
    DataSource primary = guarded();
    DataSource other = guarded();
    runner("JDBC")
        .withBean("primaryDataSource", DataSource.class, () -> primary, bd -> bd.setPrimary(true))
        .withBean("otherDataSource", DataSource.class, () -> other)
        .withBean(
            "protoSink",
            Object.class,
            () -> new JdbcAuditSink(other),
            bd -> bd.setScope(BeanDefinition.SCOPE_PROTOTYPE))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThatThrownBy(() -> ctx.getBean("protoSink"))
                  .rootCause()
                  .isInstanceOf(AgentGuardException.class)
                  .hasMessageContaining("protoSink");
            });
  }
}

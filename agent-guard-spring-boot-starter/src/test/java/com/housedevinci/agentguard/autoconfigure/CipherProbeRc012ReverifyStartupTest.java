package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.jdbc.JdbcSupport;
import com.housedevinci.agentguard.domain.AgentGuardException;
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
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.LazyInitializationBeanFactoryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.Ordered;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * B-RC12-1: every {@code JdbcAuditSink} bean is checked against the {@code DataSource} the gate
 * verified, by identity, on each path the container offers to create one.
 */
@Testcontainers
class CipherProbeRc012ReverifyStartupTest {

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
    try (InputStream in = CipherProbeRc012ReverifyStartupTest.class.getResourceAsStream(path)) {
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
    String db = "cprv_g_" + SEQ.incrementAndGet();
    exec("test", "CREATE DATABASE " + db);
    exec(db, "BEGIN", resource("/com/housedevinci/agentguard/schema-postgresql.sql"), "COMMIT");
    return ds(db);
  }

  /** The 0.1.x archive-remedy state: the live pair carries no guard. */
  private static DataSource archived() throws SQLException {
    String db = "cprv_a_" + SEQ.incrementAndGet();
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

  // ---- B-RC12-1 re-verification probes (Cipher, 2026-10-11) ----

  /** A decorator an application puts around every audit sink (metrics, tracing). */
  static final class WrappingPostProcessor implements BeanPostProcessor, Ordered {
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
      if (bean instanceof AuditSink sink) {
        return java.lang.reflect.Proxy.newProxyInstance(
            getClass().getClassLoader(),
            bean.getClass().getInterfaces(),
            (proxy, method, args) -> method.invoke(sink, args));
      }
      return bean;
    }

    @Override
    public int getOrder() {
      return 0;
    }
  }

  /** An application post-processor that needs the audit sink (records bean events). */
  static final class SinkDependingPostProcessor implements BeanPostProcessor, Ordered {
    SinkDependingPostProcessor(AuditSink sink) {}

    @Override
    public int getOrder() {
      return 0;
    }
  }

  /** Builds a JdbcAuditSink inside itself; the sink is never a bean. */
  static final class InnerSinkHolder {
    final JdbcAuditSink sink;

    InnerSinkHolder(DataSource ds, boolean verify) {
      if (verify) {
        JdbcSupport.verifyGuards(ds);
      }
      this.sink = new JdbcAuditSink(ds);
    }
  }

  /**
   * A JdbcAuditSink bean on an unguarded DataSource, wrapped by an ordered post-processor before
   * the check sees it: the check only records {@code instanceof JdbcAuditSink} after
   * initialization, so the wrapped bean is never compared and the context starts.
   */
  @Test
  void probe_sink_wrapped_by_a_post_processor_is_never_checked() throws Exception {
    DataSource audit = archived();
    runner("MEMORY")
        .withBean("wrapper", WrappingPostProcessor.class)
        .withBean(DataSource.class, () -> audit)
        .withBean("userSink", AuditSink.class, () -> new JdbcAuditSink(audit))
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  /**
   * A JdbcAuditSink bean created while an ordered application post-processor is instantiated,
   * before the check is registered: it is never recorded, and afterSingletonsInstantiated only
   * checks recorded sinks.
   */
  @Test
  void probe_sink_created_before_the_check_is_registered_is_never_checked() throws Exception {
    DataSource audit = archived();
    runner("MEMORY")
        .withBean("depending", SinkDependingPostProcessor.class)
        .withBean(DataSource.class, () -> audit)
        .withBean("userSink", AuditSink.class, () -> new JdbcAuditSink(audit))
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  /** (5) The starter's own sink and an application sink coexist: both are checked, no cycle. */
  @Test
  void verify_starter_sink_and_application_sink_are_both_checked() throws Exception {
    DataSource primary = guarded();
    DataSource other = guarded();
    runner("JDBC")
        .withBean("primaryDataSource", DataSource.class, () -> primary, bd -> bd.setPrimary(true))
        .withBean("otherDataSource", DataSource.class, () -> other)
        .withBean(
            "userSink",
            Object.class,
            () -> new JdbcAuditSink(other),
            bd -> bd.setAutowireCandidate(false))
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_DATASOURCE_MISMATCH);
              assertThat(e.getMessage()).contains("'userSink'").contains("otherDataSource");
            });
    runner("JDBC")
        .withBean("primaryDataSource", DataSource.class, () -> primary, bd -> bd.setPrimary(true))
        .withBean(
            "userSink",
            Object.class,
            () -> new JdbcAuditSink(primary),
            bd -> bd.setAutowireCandidate(false))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean("jdbcAuditSink")).isInstanceOf(JdbcAuditSink.class);
              assertThat(ctx.getBean("userSink")).isInstanceOf(JdbcAuditSink.class);
            });
  }

  /** (4) Global lazy initialization with the starter's JDBC store on an unguarded trail. */
  @Test
  void verify_lazy_initialization_still_checks_the_starter_store_at_startup() throws Exception {
    DataSource audit = archived();
    runner("JDBC")
        .withInitializer(
            c -> c.addBeanFactoryPostProcessor(new LazyInitializationBeanFactoryPostProcessor()))
        .withBean(DataSource.class, () -> audit)
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  /**
   * (3) The documented gap: an inner sink is not checked (the docs are accurate), and the remedy
   * the docs give, JdbcSupport.verifyGuards in the holder, does refuse.
   */
  @Test
  void verify_inner_sink_gap_is_as_documented_and_the_remedy_works() throws Exception {
    DataSource audit = archived();
    runner("MEMORY")
        .withBean(DataSource.class, () -> audit)
        .withBean(InnerSinkHolder.class, () -> new InnerSinkHolder(audit, false))
        .run(ctx -> assertThat(ctx).hasNotFailed());
    runner("MEMORY")
        .withBean(DataSource.class, () -> audit)
        .withBean(InnerSinkHolder.class, () -> new InnerSinkHolder(audit, true))
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
  }

  /**
   * (6) Child contexts: a child that runs the auto-configuration checks its own sinks; a child
   * without it is not checked (outside coverage, like code without the starter).
   */
  @Test
  void verify_child_context_with_and_without_the_starter() throws Exception {
    DataSource guardedParent = guarded();
    DataSource audit = archived();
    runner("JDBC")
        .withBean(DataSource.class, () -> guardedParent)
        .run(
            parent -> {
              assertThat(parent).hasNotFailed();
              runner("MEMORY")
                  .withParent(parent)
                  .withBean("childDs", DataSource.class, () -> audit, bd -> bd.setPrimary(true))
                  .withBean("childSink", AuditSink.class, () -> new JdbcAuditSink(audit))
                  .run(
                      child ->
                          assertThat(refusal(child).code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED));
              new ApplicationContextRunner()
                  .withParent(parent)
                  .withBean("childSink", AuditSink.class, () -> new JdbcAuditSink(audit))
                  .run(child -> assertThat(child).hasNotFailed());
            });
  }

  /**
   * B-RC12-4: an application JdbcDecisionStore on a second DataSource whose decision table is
   * UNLOGGED (a state the census refuses) is never compared with the checked DataSource.
   */
  @Test
  void probe_decision_store_on_a_second_datasource_is_never_compared() throws Exception {
    DataSource primary = guarded();
    DataSource other = guarded();
    try (Connection c = other.getConnection();
        Statement st = c.createStatement()) {
      st.execute("ALTER TABLE agentguard_decision SET UNLOGGED");
    }
    runner("JDBC")
        .withBean("primaryDataSource", DataSource.class, () -> primary, bd -> bd.setPrimary(true))
        .withBean("otherDataSource", DataSource.class, () -> other)
        .withBean(
            "userDecisions",
            com.housedevinci.agentguard.domain.DecisionStore.class,
            () -> new com.housedevinci.agentguard.adapter.jdbc.JdbcDecisionStore(other))
        .run(
            ctx ->
                assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.SCHEMA_DATASOURCE_MISMATCH));
  }
}

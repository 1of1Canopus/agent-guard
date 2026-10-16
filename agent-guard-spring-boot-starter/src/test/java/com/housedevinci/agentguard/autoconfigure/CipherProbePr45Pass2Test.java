package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review probes, PR 45 pass 2 (head e57ff2c). Each {@code probe_} test names what goes
 * wrong and fails on the reviewed head; each {@code attempt_} test is an attack that did not break
 * and stays green by design.
 */
@Testcontainers
class CipherProbePr45Pass2Test {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  /** 32 bytes, test-only; never a real key. */
  private static final String SECRET = "probe-only-audit-secret-32bytes!";

  /** The residual sentence the docs must carry next to the absolute claim (B-KS-8). */
  private static final String RESIDUAL = "a sink created before the check is registered";

  private static final AtomicInteger SEQ = new AtomicInteger();

  private static String url(String db) {
    return "jdbc:postgresql://"
        + POSTGRES.getHost()
        + ":"
        + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
        + "/"
        + db;
  }

  private static DataSource freshDatabase() throws SQLException {
    String db = "cp45p2_" + SEQ.incrementAndGet();
    try (Connection c =
            DriverManager.getConnection(
                url("test"), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement()) {
      st.execute("CREATE DATABASE " + db);
    }
    var ds = new PGSimpleDataSource();
    ds.setUrl(url(db));
    ds.setUser(POSTGRES.getUsername());
    ds.setPassword(POSTGRES.getPassword());
    return ds;
  }

  private static long unkeyedRows(DataSource ds) throws SQLException {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement();
        ResultSet rs =
            st.executeQuery(
                "SELECT pg_catalog.count(*) FROM agentguard_audit WHERE key_id = 'none'")) {
      rs.next();
      return rs.getLong(1);
    }
  }

  private static ApplicationContextRunner runner() {
    return new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withPropertyValues("agentguard.enabled=true", "agentguard.budgets.store=MEMORY");
  }

  private static AgentGuardException agentGuardCause(AssertableApplicationContext ctx) {
    Throwable t = ctx.getStartupFailure();
    while (t != null && !(t instanceof AgentGuardException)) {
      t = t.getCause();
    }
    return (AgentGuardException) t;
  }

  static AuditEvent event() {
    return AuditEvent.builder()
        .timestamp(Instant.parse("2026-10-16T10:00:00Z"))
        .principalId("orders-agent")
        .tool("get_order")
        .argsHash("a".repeat(64))
        .decision(AuditDecision.ALLOWED)
        .correlationId("corr-p2")
        .build();
  }

  // ---- B-KS-8: the docs say no bean can write first; a post-processor dependency can ---------

  /** An application post-processor that audits once from its own init callback. */
  static final class EarlyAuditingPostProcessor
      implements BeanPostProcessor, PriorityOrdered, InitializingBean {
    private final AuditSink sink;

    EarlyAuditingPostProcessor(AuditSink sink) {
      this.sink = sink;
    }

    @Override
    public void afterPropertiesSet() {
      sink.append(event());
    }

    @Override
    public int getOrder() {
      return Ordered.HIGHEST_PRECEDENCE;
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class PostProcessorWithUnkeyedSink {
    /** The 0.1.2 trap: one-argument constructor, unkeyed. */
    @Bean
    static AuditSink earlySink(DataSource ds) {
      return new JdbcAuditSink(ds);
    }

    @Bean
    static EarlyAuditingPostProcessor earlyAuditor(AuditSink earlySink) {
      return new EarlyAuditingPostProcessor(earlySink);
    }
  }

  private static String read(String relative) throws Exception {
    return Files.readString(Path.of("..").resolve(relative));
  }

  /**
   * docs/index.md and CHANGELOG say each sink is decided "before any other bean can write a row
   * with it". A sink that is a dependency of an application priority-ordered post-processor is
   * created before the check is registered; it writes a key_id=none row, and AG-AUDIT-003 comes
   * only at the end of startup. SECURITY-NOTES and the class doc state this residual; the two
   * user-facing pages do not. Green when the window is closed (zero rows) or both pages state it.
   */
  @Test
  void probe_docs_claim_no_write_before_the_decision_but_a_post_processor_dependency_writes()
      throws Exception {
    DataSource ds = freshDatabase();
    // first start: schema only, keyed, no traffic (zero rows, anchor still open)
    runner()
        .withBean(DataSource.class, () -> ds)
        .withPropertyValues(
            "agentguard.jdbc.initialize-schema=true", "agentguard.audit.hmac-secret=" + SECRET)
        .run(ctx -> assertThat(ctx).hasNotFailed());
    runner()
        .withBean(DataSource.class, () -> ds)
        .withPropertyValues(
            "agentguard.jdbc.initialize-schema=true", "agentguard.audit.hmac-secret=" + SECRET)
        .withUserConfiguration(PostProcessorWithUnkeyedSink.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              AgentGuardException e = agentGuardCause(ctx);
              assertThat(e).as("refused: %s", ctx.getStartupFailure()).isNotNull();
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
            });
    long written = unkeyedRows(ds);
    if (written == 0) {
      return;
    }
    assertThat(read("docs/index.md"))
        .as("docs/index.md states the residual (%d key_id=none row written first)", written)
        .contains(RESIDUAL);
    assertThat(read("CHANGELOG.md"))
        .as("CHANGELOG states the residual (%d key_id=none row written first)", written)
        .contains(RESIDUAL);
  }

  // ---- attempt: a FactoryBean product only reaches the after-hook ---------------------------

  static final class UnkeyedSinkFactory implements FactoryBean<AuditSink> {
    @Override
    public AuditSink getObject() {
      return new InMemoryAuditSink();
    }

    @Override
    public Class<?> getObjectType() {
      return AuditSink.class;
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class FactoryBeanSink {
    @Bean
    UnkeyedSinkFactory memorySinkFactory() {
      return new UnkeyedSinkFactory();
    }
  }

  /** Spring runs only the after-init hook on a FactoryBean product: still refused. */
  @Test
  void attempt_factory_bean_product_unkeyed_sink_is_refused() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withUserConfiguration(FactoryBeanSink.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              AgentGuardException e = agentGuardCause(ctx);
              assertThat(e).as("refused: %s", ctx.getStartupFailure()).isNotNull();
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
            });
  }
}

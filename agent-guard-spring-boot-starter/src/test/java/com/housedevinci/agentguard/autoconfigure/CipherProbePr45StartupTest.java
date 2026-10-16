package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.application.AuditRecorder;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.Principal;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.CustomScopeConfigurer;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.context.support.SimpleThreadScope;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review probes, PR 45 (B-SMP-1 fix: keyed default JDBC audit sink, AG-AUDIT-003). Each
 * {@code probe_} test names what goes wrong and fails on the reviewed head.
 */
@Testcontainers
class CipherProbePr45StartupTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  /** 32 bytes, test-only; never a real key. */
  private static final String SECRET = "probe-only-audit-secret-32bytes!";

  private static final String OTHER = "probe-only-other-secret-32bytes!";

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
    String db = "cp45_" + SEQ.incrementAndGet();
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

  private static long auditRows(DataSource ds) throws SQLException {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement();
        ResultSet rs =
            st.executeQuery(
                "SELECT CASE WHEN to_regclass('agentguard_audit') IS NULL THEN 0"
                    + " ELSE (SELECT pg_catalog.count(*) FROM agentguard_audit) END")) {
      rs.next();
      return rs.getLong(1);
    }
  }

  private static ApplicationContextRunner runner() {
    return new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withPropertyValues("agentguard.enabled=true", "agentguard.budgets.store=MEMORY");
  }

  private static ApplicationContextRunner jdbc(DataSource ds) {
    return runner()
        .withBean(DataSource.class, () -> ds)
        .withPropertyValues("agentguard.jdbc.initialize-schema=true");
  }

  private static Throwable rootOf(AssertableApplicationContext ctx) {
    Throwable t = ctx.getStartupFailure();
    while (t != null && t.getCause() != null && t.getCause() != t) {
      t = t.getCause();
    }
    return t;
  }

  private static AgentGuardException agentGuardCause(AssertableApplicationContext ctx) {
    Throwable t = ctx.getStartupFailure();
    while (t != null && !(t instanceof AgentGuardException)) {
      t = t.getCause();
    }
    return (AgentGuardException) t;
  }

  static void recordOne(AuditRecorder recorder) {
    recorder.record(
        new Principal("orders-agent", Set.of("AGENT"), Set.of(), null),
        "get_order",
        "{\"orderId\":\"A-1001\"}",
        "ok",
        3,
        AuditDecision.ALLOWED,
        "corr-1",
        null);
  }

  // ---- P45-1: a sink used during context start writes before the check ---------------------

  /** The 0.1.2 trap: an application JdbcAuditSink built with the one-argument constructor. */
  @Configuration(proxyBeanMethods = false)
  static class UnkeyedUserSinkWithEarlyAuditor {
    @Bean
    AuditSink userSink(ObjectProvider<AgentGuardSchemaGate> gate) {
      return new JdbcAuditSink(gate.getObject().dataSource());
    }

    /** Any bean that audits from its init callback (a warm-up, a self-test, a migration). */
    @Bean
    InitializingBean earlyAuditor(AuditRecorder recorder) {
      return () -> recordOne(recorder);
    }
  }

  /**
   * With the secret set, an unkeyed sink must be refused before it can write. On the reviewed head
   * the check runs in afterSingletonsInstantiated: an init callback has already appended a row with
   * key_id=none and fixed the anchor to keyed=false, so the trail is unkeyed forever.
   */
  @Test
  void probe_unkeyed_sink_writes_a_row_during_startup_before_the_check_refuses() throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds)
        .withPropertyValues("agentguard.audit.hmac-secret=" + SECRET)
        .withUserConfiguration(UnkeyedUserSinkWithEarlyAuditor.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              AgentGuardException e = agentGuardCause(ctx);
              assertThat(e).isNotNull();
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
            });
    assertThat(auditRows(ds)).as("rows written before the refusal").isZero();
  }

  // ---- P45-2: contradictory properties start with an application AuditChain bean -----------

  /**
   * hmac-secret set and unkeyed=true at once is refused by the starter's own auditChain bean. With
   * an application AuditChain bean that factory never runs, and the contradiction starts (with a
   * WARN that says "unkeyed" about a keyed trail).
   */
  @Test
  void probe_unkeyed_opt_out_and_secret_together_start_with_an_application_chain() {
    runner()
        .withPropertyValues(
            "agentguard.store=MEMORY",
            "agentguard.audit.hmac-secret=" + SECRET,
            "agentguard.audit.unkeyed=true")
        .withBean(
            AuditChain.class, () -> AuditChain.keyed(SECRET.getBytes(StandardCharsets.UTF_8), "k1"))
        .run(ctx -> assertThat(ctx).as("contradictory audit properties").hasFailed());
  }

  // ---- P45-3: a sink the starter cannot read starts by default ------------------------------

  /** A sink type the starter does not know. */
  static final class UnknownSink implements AuditSink {
    @Override
    public AuditEvent append(AuditEvent event) {
      return event;
    }
  }

  /**
   * Secure default: with the secret set, a sink whose mode cannot be verified must not start unless
   * the operator names it in an explicit opt-out property (which WARNs at every startup). On the
   * reviewed head it starts with a WARN only.
   */
  @Test
  void probe_unverifiable_sink_starts_by_default_with_a_secret_set() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean("customSink", AuditSink.class, UnknownSink::new)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              AgentGuardException e = agentGuardCause(ctx);
              assertThat(e).isNotNull();
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
            });
  }

  /** An unkeyed known sink behind a scoped proxy: the target is created only at first use. */
  @Configuration(proxyBeanMethods = false)
  static class ThreadScopedUnkeyedSink {
    @Bean
    static CustomScopeConfigurer threadScope() {
      var c = new CustomScopeConfigurer();
      c.setScopes(Map.of("thread", new SimpleThreadScope()));
      return c;
    }

    @Bean
    @Scope(value = "thread", proxyMode = ScopedProxyMode.INTERFACES)
    InMemoryAuditSink scopedSink() {
      return new InMemoryAuditSink();
    }
  }

  /**
   * A scoped proxy has no singleton target, so the check reads it as unknown and starts. The
   * unkeyed InMemoryAuditSink behind it is only refused at its first use, at run time.
   */
  @Test
  void probe_scoped_proxy_hides_an_unkeyed_sink_from_the_startup_check() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withUserConfiguration(ThreadScopedUnkeyedSink.class)
        .run(
            ctx -> {
              assertThat(ctx).as("unkeyed sink behind a scoped proxy").hasFailed();
              AgentGuardException e = agentGuardCause(ctx);
              assertThat(e)
                  .as(
                      "refused by the key check, not by something else: %s",
                      ctx.getStartupFailure())
                  .isNotNull();
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
            });
  }

  // ---- P45-4: the upgrade refusal does not say what happened, and allows a drop -------------

  /**
   * After the upgrade, the AG-AUDIT-001 refusal on a 0.1.x trail must tell the operator that the
   * trail may never have been keyed (B-SMP-1 advisory) and must not offer to drop the old trail:
   * dropping destroys the audit evidence the advisory says to keep.
   */
  @Test
  void probe_upgrade_refusal_hides_the_advisory_and_offers_to_drop_the_trail() throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds)
        .withPropertyValues("agentguard.audit.unkeyed=true")
        .run(ctx -> recordOne(ctx.getBean(AuditRecorder.class)));
    jdbc(ds)
        .withPropertyValues("agentguard.audit.hmac-secret=" + SECRET)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              AgentGuardException e = agentGuardCause(ctx);
              assertThat(e).isNotNull();
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_KEY_MISMATCH);
              assertThat(e.getMessage())
                  .as("names the advisory")
                  .contains("SECURITY-NOTES")
                  .as("never offers to drop the old trail")
                  .doesNotContainIgnoringCase("drop");
            });
  }

  // ---- P45-5: keyed application chain without a secret dies on a NullPointerException ------

  /**
   * An application AuditChain bean that is keyed while hmac-secret is unset: the keyring bean
   * dereferences the null secret. Startup fails, but with a NullPointerException and no error code,
   * instead of a configuration refusal that names the property.
   */
  @Test
  void probe_keyed_application_chain_without_a_secret_fails_with_a_null_pointer() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY")
        .withBean(
            AuditChain.class, () -> AuditChain.keyed(OTHER.getBytes(StandardCharsets.UTF_8), "k1"))
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(rootOf(ctx)).isNotInstanceOf(NullPointerException.class);
            });
  }

  // ---- attempt (green by design): keyed with a key other than the secret -------------------

  /**
   * Attempt: satisfy AG-AUDIT-003 with an application chain keyed by a known key that is not the
   * configured secret. The check passes (the sink is keyed), but the verifier's keyring holds the
   * secret under k1, so the trail never verifies INTACT. Detected, not silent: not a finding.
   */
  @Test
  void attempt_known_key_chain_never_verifies_intact() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean(
            AuditChain.class, () -> AuditChain.keyed(OTHER.getBytes(StandardCharsets.UTF_8), "k1"))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              recordOne(ctx.getBean(AuditRecorder.class));
              assertThat(ctx.getBean(AuditChainVerifier.class).verify().status())
                  .isNotIn(
                      AuditChainVerifier.Status.INTACT, AuditChainVerifier.Status.INTACT_UNKEYED);
            });
  }
}

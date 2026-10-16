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
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.Principal;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * B-SMP-1: with {@code agentguard.audit.hmac-secret} set, every audit sink in the context is keyed,
 * on every path that builds one; an unkeyed sink without the explicit {@code
 * agentguard.audit.unkeyed=true} opt-out refuses startup with {@code AG-AUDIT-003}.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class AuditSinkKeyCheckTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  /** 32 bytes, test-only; never a real key. */
  private static final String SECRET = "test-only-audit-secret-32-bytes!";

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
    String db = "ask_" + SEQ.incrementAndGet();
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

  private static String firstRowKeyId(DataSource ds) throws SQLException {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery("SELECT key_id FROM agentguard_audit WHERE seq = 1")) {
      assertThat(rs.next()).as("a first audit row").isTrue();
      return rs.getString(1);
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

  private static AgentGuardException refusal(AssertableApplicationContext ctx) {
    assertThat(ctx).hasFailed();
    Throwable t = ctx.getStartupFailure();
    while (t != null && !(t instanceof AgentGuardException)) {
      t = t.getCause();
    }
    assertThat(t).as("an AgentGuardException in the cause chain").isNotNull();
    return (AgentGuardException) t;
  }

  private static void recordOne(AssertableApplicationContext ctx) {
    ctx.getBean(AuditRecorder.class)
        .record(
            new Principal("orders-agent", Set.of("AGENT"), Set.of(), null),
            "get_order",
            "{\"orderId\":\"A-1001\"}",
            "ok",
            3,
            AuditDecision.ALLOWED,
            "corr-1",
            null);
  }

  // ---- path 1: the auto-configured JdbcAuditSink (store=JDBC, the default) -------------------

  @Test
  void default_jdbc_store_with_a_secret_writes_a_keyed_trail_from_row_one() throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds)
        .withPropertyValues("agentguard.audit.hmac-secret=" + SECRET)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(JdbcAuditSink.class).isKeyed()).isTrue();
              recordOne(ctx);
              assertThat(firstRowKeyId(ds)).isEqualTo("k1");
              var report = ctx.getBean(AuditChainVerifier.class).verify();
              assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.INTACT);
              assertThat(report.keyed()).isTrue();
              assertThat(report.keyIds()).containsExactly("k1");
            });
  }

  @Test
  void default_jdbc_store_uses_the_configured_key_id() throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds)
        .withPropertyValues(
            "agentguard.audit.hmac-secret=" + SECRET, "agentguard.audit.hmac-key-id=k7")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              recordOne(ctx);
              assertThat(firstRowKeyId(ds)).isEqualTo("k7");
              assertThat(ctx.getBean(AuditChainVerifier.class).verify().status())
                  .isEqualTo(AuditChainVerifier.Status.INTACT);
            });
  }

  @Test
  void default_jdbc_store_unkeyed_opt_out_starts_unkeyed_and_warns(CapturedOutput output)
      throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds)
        .withPropertyValues("agentguard.audit.unkeyed=true")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              recordOne(ctx);
              assertThat(firstRowKeyId(ds)).isEqualTo(AuditChain.UNKEYED_KEY_ID);
              assertThat(ctx.getBean(AuditChainVerifier.class).verify().status())
                  .isEqualTo(AuditChainVerifier.Status.INTACT_UNKEYED);
              assertThat(output).contains("audit trail is unkeyed");
            });
  }

  /**
   * Upgrade path: a 0.1.0 to 0.1.2 deployment with the default store wrote an unkeyed trail. With
   * the secret still set, the fixed starter now builds a keyed sink, and the sink refuses to append
   * keyed rows to that unkeyed trail ({@code AG-AUDIT-001}) at startup, before any traffic.
   */
  @Test
  void a_trail_written_unkeyed_by_0_1_2_refuses_the_now_keyed_sink_at_startup() throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds).withPropertyValues("agentguard.audit.unkeyed=true").run(ctx -> recordOne(ctx));
    jdbc(ds)
        .withPropertyValues("agentguard.audit.hmac-secret=" + SECRET)
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.AUDIT_KEY_MISMATCH));
  }

  // ---- path 2: an application-declared JdbcAuditSink bean -------------------------------------

  @Test
  void user_jdbc_sink_built_unkeyed_while_a_secret_is_set_is_refused() throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds)
        .withPropertyValues("agentguard.audit.hmac-secret=" + SECRET)
        .withUserConfiguration(UnkeyedUserJdbcSink.class)
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
              assertThat(e.getMessage())
                  .contains("'userSink'")
                  .contains("agentguard.audit.hmac-secret")
                  .doesNotContain(SECRET);
            });
  }

  @Test
  void user_jdbc_sink_built_with_the_keyed_chain_starts() throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds)
        .withPropertyValues("agentguard.audit.hmac-secret=" + SECRET)
        .withUserConfiguration(KeyedUserJdbcSink.class)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              recordOne(ctx);
              assertThat(firstRowKeyId(ds)).isEqualTo("k1");
            });
  }

  // ---- path 3: InMemoryAuditSink (store=MEMORY, auto-configured or declared) ------------------

  @Test
  void memory_store_with_a_secret_is_keyed() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(InMemoryAuditSink.class).isKeyed()).isTrue();
              recordOne(ctx);
              assertThat(ctx.getBean(AuditChainVerifier.class).verify().status())
                  .isEqualTo(AuditChainVerifier.Status.INTACT);
            });
  }

  @Test
  void user_memory_sink_built_unkeyed_while_a_secret_is_set_is_refused() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean("memSink", AuditSink.class, InMemoryAuditSink::new)
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
              assertThat(e.getMessage()).contains("'memSink'");
            });
  }

  // ---- path 4: an application-declared AuditChain bean ----------------------------------------

  /**
   * An application {@code AuditChain} bean replaces the starter's, so the starter's own refusal of
   * a missing secret never runs. The sink check still requires the explicit opt-out.
   */
  @Test
  void unkeyed_user_chain_without_secret_and_without_opt_out_is_refused() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY")
        .withBean(AuditChain.class, AuditChain::unkeyed)
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
              assertThat(e.getMessage()).contains("agentguard.audit.unkeyed");
            });
  }

  @Test
  void unkeyed_user_chain_with_a_secret_set_is_refused() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean(AuditChain.class, AuditChain::unkeyed)
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED));
  }

  @Test
  void unkeyed_user_chain_with_the_opt_out_starts_and_warns(CapturedOutput output) {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.unkeyed=true")
        .withBean(AuditChain.class, AuditChain::unkeyed)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(output).contains("audit trail is unkeyed");
            });
  }

  // ---- path 5: a proxy around a known sink -----------------------------------------------------

  @Test
  void a_proxy_around_an_unkeyed_sink_is_unwrapped_and_refused() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean(
            "proxiedSink",
            AuditSink.class,
            () -> {
              // the proxy carries every interface of the target: AuditSink, AuditReader,
              // AuditAnchor
              return (AuditSink) new ProxyFactory(new InMemoryAuditSink()).getProxy();
            })
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED));
  }

  /**
   * A post-processor that wraps the sink in a class the starter does not know must not hide the
   * unkeyed sink inside: the raw instance is seen before the wrapper replaces it.
   */
  @Test
  void a_non_aop_wrapper_around_an_unkeyed_sink_does_not_hide_it() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean("memSink", AuditSink.class, InMemoryAuditSink::new)
        .withUserConfiguration(WrappingPostProcessor.class)
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
              assertThat(e.getMessage())
                  .contains("'memSink'")
                  .contains("InMemoryAuditSink")
                  .contains("is unkeyed");
            });
  }

  @Configuration(proxyBeanMethods = false)
  static class WrappingPostProcessor {
    @Bean
    static BeanPostProcessor wrapSinks() {
      return new BeanPostProcessor() {
        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
          return bean instanceof InMemoryAuditSink inner ? new DelegatingSink(inner) : bean;
        }
      };
    }
  }

  /** A wrapper the starter cannot see into. */
  static final class DelegatingSink implements AuditSink, AuditReader {
    private final InMemoryAuditSink inner;

    DelegatingSink(InMemoryAuditSink inner) {
      this.inner = inner;
    }

    @Override
    public AuditEvent append(AuditEvent event) {
      return inner.append(event);
    }

    @Override
    public List<AuditEvent> readAfter(long afterSequence, int limit) {
      return inner.readAfter(afterSequence, limit);
    }

    @Override
    public List<AuditEvent> latest(String tenantId, int limit) {
      return inner.latest(tenantId, limit);
    }
  }

  // ---- path 6: any other AuditSink implementation ---------------------------------------------

  /** Secure default (B-KS-2): a sink the starter cannot read is refused, secret set or not. */
  @Test
  void an_unknown_sink_type_is_refused_by_default() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean("customSink", AuditSink.class, CustomSink::new)
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
              assertThat(e.getMessage())
                  .contains("'customSink'")
                  .contains("cannot verify")
                  .contains("agentguard.audit.unverified-sinks")
                  .doesNotContain(SECRET);
            });
  }

  @Test
  void an_unknown_sink_type_is_refused_also_under_the_unkeyed_opt_out() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.unkeyed=true")
        .withBean("customSink", AuditSink.class, CustomSink::new)
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED));
  }

  /** The explicit opt-out: a listed bean starts and WARNs at every startup, naming the bean. */
  @Test
  void a_listed_unknown_sink_starts_and_warns_at_every_startup(CapturedOutput output) {
    var listed =
        runner()
            .withPropertyValues(
                "agentguard.store=MEMORY",
                "agentguard.audit.hmac-secret=" + SECRET,
                "agentguard.audit.unverified-sinks=customSink")
            .withBean("customSink", AuditSink.class, CustomSink::new);
    listed.run(ctx -> assertThat(ctx).hasNotFailed());
    listed.run(ctx -> assertThat(ctx).hasNotFailed());
    assertThat(output.getAll().split("'customSink'", -1).length - 1).isGreaterThanOrEqualTo(2);
    assertThat(output).contains("cannot verify").doesNotContain(SECRET);
  }

  /** Listing a known sink does not weaken it: its mode is still read and enforced. */
  @Test
  void listing_a_known_unkeyed_sink_does_not_let_it_start() {
    runner()
        .withPropertyValues(
            "agentguard.store=MEMORY",
            "agentguard.audit.hmac-secret=" + SECRET,
            "agentguard.audit.unverified-sinks=memSink")
        .withBean("memSink", AuditSink.class, InMemoryAuditSink::new)
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED));
  }

  /** A listed name that matches no unreadable sink is a stale entry: said at every startup. */
  @Test
  void a_listed_name_that_is_no_unknown_sink_warns(CapturedOutput output) {
    runner()
        .withPropertyValues(
            "agentguard.store=MEMORY",
            "agentguard.audit.hmac-secret=" + SECRET,
            "agentguard.audit.unverified-sinks=goneSink")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(output).contains("'goneSink'");
            });
  }

  // ---- B-KS-1: decided before the sink can be used ------------------------------------------

  /** A bean that audits from its init callback must not reach an unkeyed sink. */
  @Test
  void an_unkeyed_sink_is_refused_before_an_init_callback_can_write_with_it() throws Exception {
    DataSource ds = freshDatabase();
    jdbc(ds)
        .withPropertyValues("agentguard.audit.hmac-secret=" + SECRET)
        .withUserConfiguration(UnkeyedUserJdbcSink.class, EarlyAuditor.class)
        .run(ctx -> assertThat(refusal(ctx).code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED));
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement();
        ResultSet rs =
            st.executeQuery(
                "SELECT CASE WHEN to_regclass('agentguard_audit') IS NULL THEN 0"
                    + " ELSE (SELECT pg_catalog.count(*) FROM agentguard_audit) END")) {
      rs.next();
      assertThat(rs.getLong(1)).as("rows written before the refusal").isZero();
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class EarlyAuditor {
    @Bean
    InitializingBean earlyAuditor(AuditRecorder recorder) {
      return () ->
          recorder.record(
              new Principal("orders-agent", Set.of("AGENT"), Set.of(), null),
              "get_order",
              "{}",
              "ok",
              1,
              AuditDecision.ALLOWED,
              "corr-early",
              null);
    }
  }

  // ---- B-KS-3: contradictory properties, whoever built the chain -----------------------------

  @Test
  void secret_and_unkeyed_opt_out_with_an_unkeyed_application_chain_are_refused() {
    runner()
        .withPropertyValues(
            "agentguard.store=MEMORY",
            "agentguard.audit.hmac-secret=" + SECRET,
            "agentguard.audit.unkeyed=true")
        .withBean(AuditChain.class, AuditChain::unkeyed)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(AgentGuardConfigurationException.class)
                  .hasMessageContaining("contradicts");
            });
  }

  @Test
  void secret_and_unkeyed_opt_out_with_a_keyed_application_chain_are_refused(
      CapturedOutput output) {
    runner()
        .withPropertyValues(
            "agentguard.store=MEMORY",
            "agentguard.audit.hmac-secret=" + SECRET,
            "agentguard.audit.unkeyed=true")
        .withBean(
            AuditChain.class, () -> AuditChain.keyed(SECRET.getBytes(StandardCharsets.UTF_8), "k1"))
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(AgentGuardConfigurationException.class)
                  .hasMessageContaining("contradicts");
              assertThat(output).doesNotContain("audit trail is unkeyed");
            });
  }

  // ---- B-KS-5: keyed application chain without a secret ---------------------------------------

  @Test
  void keyed_application_chain_without_a_secret_names_the_property() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY")
        .withBean(
            AuditChain.class, () -> AuditChain.keyed(SECRET.getBytes(StandardCharsets.UTF_8), "k1"))
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(AgentGuardConfigurationException.class)
                  .hasMessageContaining("agentguard.audit.hmac-secret");
            });
  }

  // ---- B-KS-7: lazy sink, and a wrapper ordered before the check -----------------------------

  /**
   * Only the end-of-start pass creates this sink: nothing injects it (the main sink is primary).
   */
  @Test
  void a_lazy_unkeyed_sink_is_refused_at_startup() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean(
            "mainSink",
            InMemoryAuditSink.class,
            () ->
                new InMemoryAuditSink(
                    AuditChain.keyed(SECRET.getBytes(StandardCharsets.UTF_8), "k1")),
            bd -> bd.setPrimary(true))
        .withBean(
            "lazySink", InMemoryAuditSink.class, InMemoryAuditSink::new, bd -> bd.setLazyInit(true))
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
              assertThat(e.getMessage()).contains("'lazySink'");
            });
  }

  /**
   * The same rule with the check alone in the context (no store check, which also creates lazy port
   * beans): the check's own end-of-start pass must create the lazy sink.
   */
  @Test
  void the_check_alone_creates_and_refuses_a_lazy_unkeyed_sink() {
    var props = new AgentGuardProperties();
    props.getAudit().setHmacSecret(SECRET);
    new ApplicationContextRunner()
        .withBean(AgentGuardProperties.class, () -> props)
        .withBean(AuditSinkKeyCheck.class, AuditSinkKeyCheck::new)
        .withBean(
            "lazySink", InMemoryAuditSink.class, InMemoryAuditSink::new, bd -> bd.setLazyInit(true))
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
              assertThat(e.getMessage()).contains("'lazySink'");
            });
  }

  /**
   * An application post-processor that runs before the check (added to the bean factory directly,
   * so it is ahead of every post-processor declared as a bean) wraps the sink in its after-hook.
   * The check's after-hook only sees the wrapper; its before-hook still sees the raw unkeyed sink.
   */
  @Test
  void a_wrapper_ordered_before_the_check_does_not_hide_an_unkeyed_sink() {
    runner()
        .withPropertyValues("agentguard.store=MEMORY", "agentguard.audit.hmac-secret=" + SECRET)
        .withBean("memSink", AuditSink.class, InMemoryAuditSink::new)
        .withInitializer(ctx -> ctx.getBeanFactory().addBeanPostProcessor(new EarlyWrapper()))
        .run(
            ctx -> {
              var e = refusal(ctx);
              assertThat(e.code()).isEqualTo(ErrorCodes.AUDIT_SINK_UNKEYED);
              assertThat(e.getMessage())
                  .contains("'memSink'")
                  .contains("InMemoryAuditSink")
                  .contains("is unkeyed");
            });
  }

  static final class EarlyWrapper implements BeanPostProcessor, PriorityOrdered {
    @Override
    public int getOrder() {
      return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
      return bean instanceof InMemoryAuditSink inner ? new DelegatingSink(inner) : bean;
    }
  }

  /** The 0.1.2 trap: the one-argument constructor, which is unkeyed. */
  @Configuration(proxyBeanMethods = false)
  static class UnkeyedUserJdbcSink {
    @Bean
    AuditSink userSink(ObjectProvider<AgentGuardSchemaGate> gate) {
      return new JdbcAuditSink(gate.getObject().dataSource());
    }
  }

  /** The documented way to declare one's own sink: pass the starter's {@code AuditChain}. */
  @Configuration(proxyBeanMethods = false)
  static class KeyedUserJdbcSink {
    @Bean
    JdbcAuditSink userSink(ObjectProvider<AgentGuardSchemaGate> gate, AuditChain chain) {
      return new JdbcAuditSink(gate.getObject().dataSource(), chain);
    }
  }

  /** A sink type the starter does not know. */
  static final class CustomSink implements AuditSink, AuditReader {
    @Override
    public AuditEvent append(AuditEvent event) {
      return event;
    }

    @Override
    public List<AuditEvent> readAfter(long afterSequence, int limit) {
      return List.of();
    }

    @Override
    public List<AuditEvent> latest(String tenantId, int limit) {
      return List.of();
    }
  }
}

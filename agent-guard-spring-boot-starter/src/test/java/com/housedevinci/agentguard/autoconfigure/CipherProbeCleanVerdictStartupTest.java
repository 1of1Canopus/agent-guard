package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Cipher clean-verdict pass on f27c45e: startup-check ordering and message hygiene. Temporary. */
@Testcontainers
class CipherProbeCleanVerdictStartupTest {

  private static final String S1 = "A".repeat(32);
  private static final String S2 = "B".repeat(32);

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  static HikariDataSource ds;

  @BeforeAll
  static void open() {
    ds = new HikariDataSource();
    ds.setJdbcUrl(POSTGRES.getJdbcUrl());
    ds.setUsername(POSTGRES.getUsername());
    ds.setPassword(POSTGRES.getPassword());
  }

  @AfterAll
  static void close() {
    ds.close();
  }

  private static boolean auditTableExists() throws Exception {
    try (var c = ds.getConnection();
        Statement st = c.createStatement();
        var rs = st.executeQuery("SELECT to_regclass('agentguard_audit') IS NOT NULL")) {
      rs.next();
      return rs.getBoolean(1);
    }
  }

  /**
   * H2: the unkeyed/secret contradiction must be refused before the schema step writes anything.
   * The DataSource is real and the store is JDBC, so if any bean touched the database first the
   * audit table would exist after the failure.
   */
  @Test
  void probe_the_unkeyed_contradiction_fires_before_the_database_is_touched() throws Exception {
    try (var c = ds.getConnection();
        Statement st = c.createStatement()) {
      st.execute("DROP TABLE IF EXISTS agentguard_audit_anchor");
      st.execute("DROP TABLE IF EXISTS agentguard_audit");
      st.execute("DROP TABLE IF EXISTS agentguard_decision");
      st.execute("DROP TABLE IF EXISTS agentguard_budget");
    }
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withBean(DataSource.class, () -> ds, bd -> bd.setDestroyMethodName(""))
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.store=JDBC",
            "agentguard.audit.unkeyed=true",
            "agentguard.audit.hmac-secret=" + S1)
        .run(ctx -> assertThat(ctx).hasFailed());
    assertThat(auditTableExists()).isFalse();
  }

  /** No startup failure message may carry key material. */
  @Test
  void probe_no_startup_failure_message_carries_key_material() {
    var runner =
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
            .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY");

    runner
        .withPropertyValues("agentguard.audit.unkeyed=true", "agentguard.audit.hmac-secret=" + S1)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(stack(ctx.getStartupFailure())).doesNotContain(S1).doesNotContain(S2);
            });

    runner
        .withPropertyValues(
            "agentguard.audit.hmac-secret=" + S1,
            "agentguard.audit.hmac-key-id=k1",
            "agentguard.audit.hmac-keys.k1=" + S2)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(stack(ctx.getStartupFailure())).doesNotContain(S1).doesNotContain(S2);
            });

    runner
        .withPropertyValues(
            "agentguard.audit.hmac-secret=" + S1, "agentguard.audit.hmac-keys.k9=short")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(stack(ctx.getStartupFailure())).doesNotContain("short");
            });
  }

  /** A same-secret duplicate entry under the appending id stays a pure no-op. */
  @Test
  void probe_a_same_secret_ring_duplicate_is_a_no_op() {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.store=MEMORY",
            "agentguard.audit.hmac-secret=" + S1,
            "agentguard.audit.hmac-key-id=k1",
            "agentguard.audit.hmac-keys.k1=" + S1,
            "agentguard.audit.hmac-keys.k0=" + S2)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              @SuppressWarnings("unchecked")
              var ring = (java.util.Map<String, byte[]>) ctx.getBean("auditKeyring");
              assertThat(ring).containsOnlyKeys("k1", "k0");
              assertThat(ring.get("k1"))
                  .isEqualTo(S1.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            });
  }

  private static String stack(Throwable t) {
    var sw = new java.io.StringWriter();
    t.printStackTrace(new java.io.PrintWriter(sw));
    return sw.toString();
  }
}

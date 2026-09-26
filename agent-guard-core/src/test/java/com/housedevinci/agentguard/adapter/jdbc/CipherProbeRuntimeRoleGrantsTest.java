package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThatCode;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review of the "Database roles" grant block (branch docs/runtime-role-grants). The role
 * below is created with EXACTLY the statements the documentation tells an operator to paste,
 * nothing else. Temporary probe, not part of the module's own suite.
 */
@Testcontainers
class CipherProbeRuntimeRoleGrantsTest {

  /** The grant block, verbatim from docs/index.md "Database roles". */
  private static final String[] DOCUMENTED_GRANTS = {
    "GRANT SELECT, INSERT ON agentguard_audit TO agentguard_runtime",
    "GRANT USAGE ON SEQUENCE agentguard_audit_seq_seq TO agentguard_runtime",
    "GRANT SELECT, INSERT, UPDATE ON agentguard_decision, agentguard_audit_anchor TO agentguard_runtime",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON agentguard_budget TO agentguard_runtime"
  };

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  static HikariDataSource ownerDs;
  static HikariDataSource runtimeDs;

  @BeforeAll
  static void open() throws SQLException {
    ownerDs = pool(POSTGRES.getUsername(), POSTGRES.getPassword());
    JdbcSupport.initializeSchema(ownerDs);
    asOwner("CREATE ROLE agentguard_runtime LOGIN PASSWORD 'probe'");
    for (String grant : DOCUMENTED_GRANTS) {
      asOwner(grant);
    }
    runtimeDs = pool("agentguard_runtime", "probe");
  }

  private static HikariDataSource pool(String user, String password) {
    var pool = new HikariDataSource();
    pool.setJdbcUrl(POSTGRES.getJdbcUrl());
    pool.setUsername(user);
    pool.setPassword(password);
    pool.setMaximumPoolSize(2);
    return pool;
  }

  private static void asOwner(String sql) throws SQLException {
    try (var c = ownerDs.getConnection();
        Statement st = c.createStatement()) {
      st.execute(sql);
    }
  }

  @AfterAll
  static void close() {
    if (runtimeDs != null) {
      runtimeDs.close();
    }
    ownerDs.close();
  }

  /**
   * Finding: the documented grant block omits DELETE on agentguard_budget, which
   * JdbcBudgetStore.incrementAndGet issues itself on every PURGE_EVERY-th call
   * (JdbcBudgetStore.purgeExpired, "DELETE FROM agentguard_budget WHERE expires_at &lt; ?"). The
   * call is not guarded by a try/catch, so the JdbcAccessException propagates out of budget
   * enforcement and fails that guarded call. Same defect class as the missing sequence USAGE this
   * branch fixes: the documented role cannot complete the runtime write path.
   */
  @Test
  void probe_budget_purge_is_denied_to_the_documented_runtime_role() {
    var store = new JdbcBudgetStore(runtimeDs, Clock.systemUTC());
    assertThatCode(
            () -> {
              for (int i = 0; i < JdbcBudgetStore.PURGE_EVERY; i++) {
                store.incrementAndGet("cipher-probe-key", 1, Duration.ofMinutes(5));
              }
            })
        .doesNotThrowAnyException();
  }
}

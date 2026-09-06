package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Cipher probes against the real PostgreSQL adapters: what the application's own database
 * credentials (the ones that ran the schema) can do to the "append-only" trail, and what the
 * verifier then reports.
 */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CipherProbeJdbcTest {

  @Container
  static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

  static HikariDataSource ds;

  @BeforeAll
  static void schema() {
    ds = new HikariDataSource();
    ds.setJdbcUrl(POSTGRES.getJdbcUrl());
    ds.setUsername(POSTGRES.getUsername());
    ds.setPassword(POSTGRES.getPassword());
    ds.setMaximumPoolSize(4);
    JdbcSupport.initializeSchema(ds);
  }

  @AfterAll
  static void close() {
    ds.close();
  }

  private static AuditEvent event(Instant ts) {
    return AuditEvent.builder()
        .timestamp(ts)
        .principalId("u1")
        .tool("t")
        .argsHash("a".repeat(64))
        .decision(AuditDecision.ALLOWED)
        .correlationId("c")
        .build();
  }

  private static void sql(String statement) throws SQLException {
    try (var c = ds.getConnection();
        Statement st = c.createStatement()) {
      st.execute(statement);
    }
  }

  private static long count(String table) throws SQLException {
    try (var c = ds.getConnection();
        Statement st = c.createStatement();
        var rs = st.executeQuery("SELECT count(*) FROM " + table)) {
      rs.next();
      return rs.getLong(1);
    }
  }

  @Test
  @Order(1)
  void probe_sub_millisecond_timestamp_breaks_verification_after_storage() {
    var sink = new JdbcAuditSink(ds);
    var appended = sink.append(event(Instant.parse("2026-09-06T10:00:00.123456789Z")));
    var stored = sink.readAfter(0, 10).get(0);
    assertThat(stored.timestamp()).isNotEqualTo(appended.timestamp()); // micros in Postgres
    var report = new AuditChainVerifier(sink).verify();
    assertThat(report.intact()).isFalse();
    assertThat(report.brokenAtSequence()).isEqualTo(appended.sequence());
  }

  @Test
  @Order(2)
  void probe_truncate_is_not_blocked_by_the_row_trigger_and_the_verifier_reports_intact()
      throws SQLException {
    var sink = new JdbcAuditSink(ds);
    assertThatThrownBy(() -> sql("DELETE FROM agentguard_audit"))
        .hasMessageContaining("append-only");
    assertThatThrownBy(() -> sql("UPDATE agentguard_audit SET tool = 'x'"))
        .hasMessageContaining("append-only");

    sql("TRUNCATE agentguard_audit");
    assertThat(count("agentguard_audit")).isZero();
    var report = new AuditChainVerifier(sink).verify();
    assertThat(report.intact()).isTrue();
    assertThat(report.verified()).isZero();
  }

  @Test
  @Order(3)
  void probe_the_schema_owner_can_disable_the_trigger_and_tail_deletion_is_undetectable()
      throws SQLException {
    var sink = new JdbcAuditSink(ds);
    var t0 = Instant.parse("2026-09-06T10:00:00Z");
    sink.append(event(t0));
    sink.append(event(t0.plusSeconds(1)));
    var last = sink.append(event(t0.plusSeconds(2)));
    assertThat(new AuditChainVerifier(sink).verify().verified()).isEqualTo(3);

    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only");
    sql("DELETE FROM agentguard_audit WHERE seq = " + last.sequence());
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER agentguard_audit_append_only");

    var report = new AuditChainVerifier(sink).verify();
    assertThat(report.intact()).isTrue();
    assertThat(report.verified()).isEqualTo(2);
  }

  @Test
  @Order(4)
  void probe_expired_budget_rows_are_never_purged() throws SQLException {
    var now = Instant.parse("2026-09-06T10:00:00Z");
    var store = new JdbcBudgetStore(ds, Clock.fixed(now, ZoneOffset.UTC));
    for (int i = 0; i < 20; i++) {
      store.incrementAndGet(
          "agentguard:budget:CONVERSATION:STEPS:conv-" + i + ":0", 1, Duration.ofMillis(1));
    }
    var later = new JdbcBudgetStore(ds, Clock.fixed(now.plusSeconds(3600), ZoneOffset.UTC));
    assertThat(later.current("agentguard:budget:CONVERSATION:STEPS:conv-1:0")).isZero();
    assertThat(count("agentguard_budget")).isEqualTo(20);
  }

  @Test
  @Order(5)
  void probe_key_longer_than_the_column_fails_the_call_closed() {
    var store = new JdbcBudgetStore(ds, Clock.systemUTC());
    assertThatThrownBy(() -> store.incrementAndGet("k".repeat(600), 1, Duration.ofMinutes(1)))
        .isInstanceOf(JdbcSupport.JdbcAccessException.class)
        .hasMessageContaining("too long");
  }
}

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
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher probes against the real PostgreSQL adapters: what the application's own database
 * credentials (the ones that ran the schema) can do to the "append-only" trail, and what the
 * verifier then reports.
 */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CipherProbeJdbcTest {

  @Container
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

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

  @Test // M2 flipped
  @Order(1)
  void sub_millisecond_timestamps_round_trip_and_verify() {
    var sink = new JdbcAuditSink(ds);
    var appended = sink.append(event(Instant.parse("2026-09-06T10:00:00.123456789Z")));
    var stored = sink.readAfter(0, 10).get(0);
    assertThat(stored.timestamp()).isEqualTo(appended.timestamp());
    assertThat(stored.timestamp()).isEqualTo(Instant.parse("2026-09-06T10:00:00.123Z"));
    var report = new AuditChainVerifier(sink).verify();
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.INTACT);
  }

  @Test // M2 flipped
  @Order(2)
  void truncate_is_refused_like_update_and_delete() throws SQLException {
    assertThatThrownBy(() -> sql("DELETE FROM agentguard_audit"))
        .hasMessageContaining("append-only");
    assertThatThrownBy(() -> sql("UPDATE agentguard_audit SET tool = 'x'"))
        .hasMessageContaining("append-only");
    assertThatThrownBy(() -> sql("TRUNCATE agentguard_audit")).hasMessageContaining("append-only");
    assertThat(count("agentguard_audit")).isEqualTo(1);
  }

  @Test // M2 flipped: the owner can still disable triggers, but the anchor exposes the deletion
  @Order(3)
  void tail_deletion_by_the_schema_owner_is_reported_as_anchor_mismatch() throws SQLException {
    var sink = new JdbcAuditSink(ds);
    var t0 = Instant.parse("2026-09-06T10:00:00Z");
    sink.append(event(t0));
    var last = sink.append(event(t0.plusSeconds(1)));
    assertThat(new AuditChainVerifier(sink).verify().verified()).isEqualTo(3);
    assertThat(sink.anchor())
        .contains(new com.housedevinci.agentguard.domain.AuditAnchor.Anchor(last.hash(), 3));

    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only");
    sql("DELETE FROM agentguard_audit WHERE seq = " + last.sequence());
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER agentguard_audit_append_only");

    var report = new AuditChainVerifier(sink).verify();
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.ANCHOR_MISMATCH);
    assertThat(report.intact()).isFalse();
    assertThat(report.verified()).isEqualTo(2);

    // the same owner truncating with triggers disabled: rows gone, anchor says otherwise
    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER ALL");
    sql("TRUNCATE agentguard_audit");
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER ALL");
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.ANCHOR_MISMATCH);
  }

  @Test // L8 flipped
  @Order(4)
  void expired_budget_rows_are_purged_and_long_subjects_fit() throws SQLException {
    var now = Instant.parse("2026-09-06T10:00:00Z");
    var store = new JdbcBudgetStore(ds, Clock.fixed(now, ZoneOffset.UTC));
    for (int i = 0; i < 20; i++) {
      store.incrementAndGet(
          "agentguard:budget:CONVERSATION:STEPS:conv-" + i + ":0", 1, Duration.ofMillis(1));
    }
    assertThat(count("agentguard_budget")).isGreaterThanOrEqualTo(20);
    var later = new JdbcBudgetStore(ds, Clock.fixed(now.plus(Duration.ofDays(2)), ZoneOffset.UTC));
    assertThat(later.current("agentguard:budget:CONVERSATION:STEPS:conv-1:0")).isZero();
    assertThat(later.purgeExpired(now.plus(Duration.ofDays(2)))).isGreaterThanOrEqualTo(20);
    assertThat(count("agentguard_budget")).isZero();
    // automatic purge every 1000 increments
    for (int i = 0; i < 20; i++) {
      store.incrementAndGet(
          "agentguard:budget:CONVERSATION:STEPS:again-" + i + ":0", 1, Duration.ofMillis(1));
    }
    for (int i = 0; i < JdbcBudgetStore.PURGE_EVERY; i++) {
      later.incrementAndGet("agentguard:budget:PRINCIPAL:TOOL_CALLS:p:0", 1, Duration.ofHours(1));
    }
    assertThat(count("agentguard_budget")).isEqualTo(1);
    // a 600-character key is stored (column is text) and a long subject is hashed anyway
    assertThat(store.incrementAndGet("k".repeat(600), 1, Duration.ofMinutes(1))).isEqualTo(1);
    var limit =
        new com.housedevinci.agentguard.domain.BudgetLimit(
            com.housedevinci.agentguard.domain.BudgetScope.CONVERSATION,
            com.housedevinci.agentguard.domain.BudgetKind.STEPS,
            Duration.ofHours(1),
            5);
    assertThat(limit.key("c".repeat(5000), now)).hasSizeLessThan(200);
  }
}

package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** the security review re-verification probes for the anchor row introduced by the M2 fix. */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CipherProbeReverifyJdbcTest {

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

  @Test
  @Order(1)
  void probe_owner_can_rewrite_the_anchor_to_hide_a_tail_deletion() throws SQLException {
    var sink = new JdbcAuditSink(ds);
    var t0 = Instant.parse("2026-09-06T10:00:00Z");
    var first = sink.append(event(t0));
    var second = sink.append(event(t0.plusSeconds(1)));
    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER ALL");
    sql("DELETE FROM agentguard_audit WHERE seq = " + second.sequence());
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER ALL");
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.ANCHOR_MISMATCH);
    // the anchor table has no trigger: the same owner (or a runtime role with UPDATE on it) resets
    // it
    sql(
        "UPDATE agentguard_audit_anchor SET head_hash = '"
            + first.hash()
            + "', row_count = 1 WHERE id = 1");
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
  }

  @Test // R2 flipped: rows without an anchor re-anchor from the head, and the schema seeds the row
  @Order(2)
  void trail_without_anchor_row_continues_from_the_real_head() throws SQLException {
    var sink = new JdbcAuditSink(ds);
    sql("DELETE FROM agentguard_audit_anchor");
    var head = sink.latest(1).get(0);
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
    var appended = sink.append(event(Instant.parse("2026-09-06T11:00:00Z")));
    assertThat(appended.prevHash()).isEqualTo(head.hash());
    var after = new AuditChainVerifier(sink).verify();
    assertThat(after.status()).isEqualTo(AuditChainVerifier.Status.INTACT);
    assertThat(sink.anchor()).isPresent();
    assertThat(sink.anchor().get().rowCount()).isEqualTo(after.verified());

    // and the idempotent schema step seeds a missing anchor from the existing rows
    sql("DELETE FROM agentguard_audit_anchor");
    JdbcSupport.initializeSchema(ds);
    assertThat(sink.anchor())
        .contains(
            new com.housedevinci.agentguard.domain.AuditAnchor.Anchor(
                appended.hash(), after.verified()));
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
  }
}

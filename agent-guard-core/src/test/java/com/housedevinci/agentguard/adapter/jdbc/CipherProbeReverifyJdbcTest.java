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
import org.testcontainers.utility.DockerImageName;

/** Cipher re-verification probes for the anchor row introduced by the M2 fix. */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CipherProbeReverifyJdbcTest {

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

  @Test // R4 flipped: the anchor only advances; a reset is refused (the owner can still drop the
  // trigger)
  @Order(1)
  void anchor_cannot_be_reset_to_hide_a_tail_deletion() throws SQLException {
    var sink = new JdbcAuditSink(ds);
    var t0 = Instant.parse("2026-09-06T10:00:00Z");
    var first = sink.append(event(t0));
    var second = sink.append(event(t0.plusSeconds(1)));
    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER ALL");
    sql("DELETE FROM agentguard_audit WHERE seq = " + second.sequence());
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER ALL");
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.ANCHOR_MISMATCH);
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () ->
                sql(
                    "UPDATE agentguard_audit_anchor SET head_hash = '"
                        + first.hash()
                        + "', row_count = 1 WHERE id = 1"))
        .hasMessageContaining("only advances");
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.ANCHOR_MISMATCH);
    // an append after the deletion chains to the anchor's head, which is gone: BROKEN, still
    // detected
    sink.append(event(t0.plusSeconds(2)));
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.BROKEN);
    // repair for the following test (owner powers): trim to the first row, reset the anchor
    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER ALL");
    sql("ALTER TABLE agentguard_audit_anchor DISABLE TRIGGER ALL");
    sql("DELETE FROM agentguard_audit WHERE seq > " + first.sequence());
    sql("UPDATE agentguard_audit_anchor SET head_hash = '" + first.hash() + "', row_count = 1");
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER ALL");
    sql("ALTER TABLE agentguard_audit_anchor ENABLE TRIGGER ALL");
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT_UNKEYED);
  }

  /**
   * R2, superseded by the amendment after Cipher's design review of keyed-from-birth: a missing
   * anchor on a non-empty trail is no longer re-derived from the trail head (that was exactly the
   * "guess a keyed value from row data" the anchor exists to make unnecessary — the same class of
   * gap as the retired {@code keyed_from_seq} F1/F2 findings). It is refused instead, on both the
   * next append and the next verification; the schema step does not resurrect it either, since it
   * only ever seeds the anchor for a genuinely empty trail.
   */
  @Test
  @Order(2)
  void a_trail_without_an_anchor_row_refuses_to_append_and_reports_no_anchor() throws SQLException {
    var sink = new JdbcAuditSink(ds);
    sink.append(event(Instant.parse("2026-09-06T11:00:00Z")));
    sql("ALTER TABLE agentguard_audit_anchor DISABLE TRIGGER ALL");
    sql("DELETE FROM agentguard_audit_anchor");
    sql("ALTER TABLE agentguard_audit_anchor ENABLE TRIGGER ALL");

    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> sink.append(event(Instant.parse("2026-09-06T11:00:01Z"))))
        .isInstanceOf(com.housedevinci.agentguard.domain.AgentGuardException.class)
        .extracting(e -> ((com.housedevinci.agentguard.domain.AgentGuardException) e).code())
        .isEqualTo(com.housedevinci.agentguard.domain.ErrorCodes.AUDIT_ANCHOR_MISSING);

    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.NO_ANCHOR);

    // the schema step does not resurrect it either — it only ever seeds an empty trail
    JdbcSupport.initializeSchema(ds);
    assertThat(sink.anchor()).isEmpty();
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> new JdbcAuditSink(ds))
        .isInstanceOf(com.housedevinci.agentguard.domain.AgentGuardException.class);
  }
}

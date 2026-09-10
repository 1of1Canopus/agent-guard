package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * the security review verification pass on 722e9a5 (keyed-from-birth). Attack probes, not
 * regression cover.
 */
@Testcontainers
class CipherProbeKeyedBirthJdbcTest {

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
    ds.setMaximumPoolSize(8);
  }

  @AfterAll
  static void close() {
    ds.close();
  }

  @BeforeEach
  void fresh() throws SQLException {
    sql("DROP TABLE IF EXISTS agentguard_audit_anchor");
    sql("DROP TABLE IF EXISTS agentguard_audit");
    JdbcSupport.initializeSchema(ds);
  }

  private static AuditEvent event(int i) {
    return AuditEvent.builder()
        .timestamp(Instant.parse("2026-09-07T10:00:00Z").plusSeconds(i))
        .principalId("u1")
        .tool("t")
        .argsHash("a".repeat(64))
        .decision(AuditDecision.ALLOWED)
        .correlationId("c" + i)
        .build();
  }

  private static void sql(String statement) throws SQLException {
    try (var c = ds.getConnection();
        Statement st = c.createStatement()) {
      st.execute(statement);
    }
  }

  private static List<String> query(String statement) throws SQLException {
    var out = new ArrayList<String>();
    try (var c = ds.getConnection();
        Statement st = c.createStatement();
        var rs = st.executeQuery(statement)) {
      while (rs.next()) {
        out.add(rs.getString(1));
      }
    }
    return out;
  }

  private static byte[] key(int b) {
    var k = new byte[32];
    Arrays.fill(k, (byte) b);
    return k;
  }

  // ---- G1: an existing pre-redesign database cannot be upgraded in place ----

  /**
   * There is no upgrade path from a database written before {@code agentguard_audit.key_id} existed
   * (this branch is unreleased): the schema step detects the missing column up front and fails with
   * a clear, actionable message, rather than aborting later on the append-only trigger or on a
   * missing-column error from an INSERT.
   */
  @Test
  void probe_an_existing_database_with_rows_cannot_run_the_new_schema_step() throws Exception {
    new JdbcAuditSink(ds, AuditChain.unkeyed()).append(event(1));
    // simulate a database written before key_id existed (the column is the only difference that
    // matters here; the append-only trigger and the row are already in place)
    sql("ALTER TABLE agentguard_audit DROP COLUMN key_id");

    assertThatThrownBy(() -> JdbcSupport.initializeSchema(ds))
        .hasMessageContaining("audit schema predates keyed-from-birth")
        .hasMessageContaining("archive the table and start a new trail");
  }

  /**
   * The same for the anchor: a database whose {@code agentguard_audit_anchor} predates the {@code
   * keyed} column is refused with the same clear message, not left to fail later on the anchor's
   * monotonic trigger or a missing-column error from an INSERT.
   */
  @Test
  void probe_an_existing_anchor_row_cannot_be_backfilled_with_keyed() throws Exception {
    new JdbcAuditSink(ds, AuditChain.unkeyed()).append(event(1));
    sql("ALTER TABLE agentguard_audit_anchor DROP COLUMN keyed");

    assertThatThrownBy(() -> JdbcSupport.initializeSchema(ds))
        .hasMessageContaining("audit schema predates keyed-from-birth")
        .hasMessageContaining("archive the table and start a new trail");
  }

  /** Control: re-running the schema step on a current, non-empty database is idempotent. */
  @Test
  void confirms_the_schema_step_is_idempotent_on_a_current_non_empty_database() throws Exception {
    var sink = new JdbcAuditSink(ds, AuditChain.keyed(key(7), "k1"));
    sink.append(event(1));
    JdbcSupport.initializeSchema(ds);
    JdbcSupport.initializeSchema(ds);
    var report = new AuditChainVerifier(sink, sink, Map.of("k1", key(7))).verify();
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.INTACT);
  }

  // ---- G2: key id relabel by an attacker who owns the table ----

  /**
   * An attacker who can disable the append-only trigger relabels a row's {@code key_id} to another
   * id the verifier holds. The id is inside the hashed material, so the hash no longer recomputes:
   * BROKEN at that row, never INTACT.
   */
  @Test
  void confirms_a_key_id_relabel_to_a_held_key_still_breaks_the_hash() throws Exception {
    var sink = new JdbcAuditSink(ds, AuditChain.keyed(key(7), "k1"));
    sink.append(event(1));
    sink.append(event(2));
    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only");
    sql("UPDATE agentguard_audit SET key_id = 'k2' WHERE seq = 2");
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER agentguard_audit_append_only");

    var report = new AuditChainVerifier(sink, sink, Map.of("k1", key(7), "k2", key(9))).verify();
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(report.brokenAtSequence()).isEqualTo(2);
  }

  /** And relabelling to an id nobody holds is BROKEN too, not skipped. */
  @Test
  void confirms_a_key_id_relabel_to_an_unheld_key_is_broken() throws Exception {
    var sink = new JdbcAuditSink(ds, AuditChain.keyed(key(7), "k1"));
    sink.append(event(1));
    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only");
    sql("UPDATE agentguard_audit SET key_id = 'kZ' WHERE seq = 1");
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER agentguard_audit_append_only");

    assertThat(new AuditChainVerifier(sink, sink, Map.of("k1", key(7))).verify().status())
        .isEqualTo(AuditChainVerifier.Status.BROKEN);
  }

  // ---- G3: two instances, both keyed, different ids, one missing from the keyring ----

  @Test
  void confirms_two_keyed_instances_with_different_ids_both_append_and_verify_together()
      throws Exception {
    var a = new JdbcAuditSink(ds, AuditChain.keyed(key(1), "k1"));
    var b = new JdbcAuditSink(ds, AuditChain.keyed(key(2), "k2"));
    a.append(event(1));
    b.append(event(2));
    a.append(event(3));

    assertThat(query("SELECT string_agg(key_id, ',' ORDER BY seq) FROM agentguard_audit"))
        .containsExactly("k1,k2,k1");
    assertThat(new AuditChainVerifier(a, a, Map.of("k1", key(1), "k2", key(2))).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
    var partial = new AuditChainVerifier(a, a, Map.of("k2", key(2))).verify();
    assertThat(partial.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(partial.brokenAtSequence()).isEqualTo(1);
  }

  // ---- G4: no secret material in refusal messages ----

  @Test
  void confirms_no_refusal_message_carries_key_material() throws Exception {
    var secret = "S3CRET-".repeat(8).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    new JdbcAuditSink(ds, AuditChain.keyed(secret, "k1")).append(event(1));
    assertThatThrownBy(() -> new JdbcAuditSink(ds, AuditChain.unkeyed()))
        .satisfies(
            t -> {
              assertThat(t.getMessage()).doesNotContain("S3CRET");
            });
    sql("ALTER TABLE agentguard_audit_anchor DISABLE TRIGGER agentguard_audit_anchor_no_delete");
    sql("DELETE FROM agentguard_audit_anchor");
    sql("ALTER TABLE agentguard_audit_anchor ENABLE TRIGGER agentguard_audit_anchor_no_delete");
    assertThatThrownBy(() -> new JdbcAuditSink(ds, AuditChain.keyed(secret, "k1")))
        .satisfies(t -> assertThat(t.getMessage()).doesNotContain("S3CRET"));
  }
}

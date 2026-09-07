package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Design change: keyed-from-birth (Dollar ruling, QUESTIONS.md #20). A trail is keyed from row 1 or
 * unkeyed forever — no mixing, no later switch. {@code agentguard_audit_anchor.keyed} (a plain
 * {@code boolean}, set once at the first append and immutable afterwards) replaces the earlier
 * {@code keyed_from_seq} mechanism (and the F1/F2 findings against it, which no longer apply: there
 * is no sequence arithmetic left to get wrong). This class replaces Cipher's F1–F4 probes; see
 * {@code docs/SECURITY-REVIEW-feat-agent-guard-core.md}, "Design change: keyed-from-birth", for the
 * old-probe -> new-probe map.
 */
@Testcontainers
class CipherProbeAnchorKeyingJdbcTest {

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

  private static AuditChain keyedChain() {
    var key = new byte[32];
    Arrays.fill(key, (byte) 7);
    return AuditChain.keyed(key);
  }

  /**
   * Replaces F4. A rolling restart that flips {@code agentguard.audit.hmac-secret} on must not be
   * able to leave an unkeyed row in a trail the anchor already records as keyed: the still-unkeyed
   * instance is refused, not merely the append that would have corrupted the trail.
   */
  @Test
  void an_unkeyed_instance_is_refused_once_the_trail_is_keyed() throws Exception {
    var first = new JdbcAuditSink(ds, keyedChain()); // first ever append: anchor.keyed := true
    first.append(event(1));
    assertThat(query("SELECT keyed::text FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("true");

    // the not-yet-restarted instance tries to keep serving traffic without the secret
    assertThatThrownBy(() -> new JdbcAuditSink(ds))
        .isInstanceOf(AgentGuardException.class)
        .extracting(e -> ((AgentGuardException) e).code())
        .isEqualTo(ErrorCodes.AUDIT_KEY_MISMATCH);

    // the trail itself is untouched
    assertThat(new AuditChainVerifier(first, first, keyedChain()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
  }

  /**
   * Replaces F4's mirror image, and replaces Cipher's C6 probe (superseded by keyed-from-birth,
   * QUESTIONS.md #20): a newly-keyed instance must not silently start signing a trail that began
   * unkeyed and was never meant to switch. "Enabling {@code agentguard.audit.hmac-secret} on a
   * running installation" is refused at startup, naming the property and the remedy, rather than
   * accommodated (the old C6 goal, no longer the design).
   */
  @Test
  void a_keyed_instance_is_refused_on_a_trail_that_started_unkeyed() throws Exception {
    var first = new JdbcAuditSink(ds); // first ever append: anchor.keyed := false
    first.append(event(1));
    assertThat(query("SELECT keyed::text FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("false");

    assertThatThrownBy(() -> new JdbcAuditSink(ds, keyedChain()))
        .isInstanceOf(AgentGuardException.class)
        .hasMessageContaining("agentguard.audit.hmac-secret")
        .hasMessageContaining("start a new trail")
        .extracting(e -> ((AgentGuardException) e).code())
        .isEqualTo(ErrorCodes.AUDIT_KEY_MISMATCH);
  }

  /**
   * The refusal also fires mid-lifetime, on append, not only at construction — e.g. the anchor row
   * was seeded (or lost and re-derived) after this instance was already constructed against an
   * empty table.
   */
  @Test
  void the_mismatch_is_also_refused_on_append_not_only_at_construction() throws Exception {
    var unkeyed = new JdbcAuditSink(ds); // constructed while the trail is still empty: no mismatch
    var keyedFirst = new JdbcAuditSink(ds, keyedChain());
    keyedFirst.append(event(1)); // now the trail is keyed

    assertThatThrownBy(() -> unkeyed.append(event(2)))
        .isInstanceOf(AgentGuardException.class)
        .hasMessageContaining("agentguard.audit.hmac-secret")
        .extracting(e -> ((AgentGuardException) e).code())
        .isEqualTo(ErrorCodes.AUDIT_KEY_MISMATCH);
  }

  /**
   * Replaces the first half of the old F3 probe. A table-owning attacker relinks every row unkeyed
   * from GENESIS and stamps {@code chain_version = 'ag1'} throughout — internally consistent, but
   * the anchor's {@code keyed} column (outside the rows they rewrite, and immutable once set) still
   * says this trail must be keyed from row 1. The verifier catches the mismatch at the very first
   * row, without needing to recompute any hash.
   */
  @Test
  void the_whole_trail_downgrade_is_broken_because_the_anchor_says_keyed() throws Exception {
    var keyed = new JdbcAuditSink(ds, keyedChain());
    keyed.append(event(1));
    keyed.append(event(2));
    assertThat(AuditChainVerifier.of(keyed, keyedChain()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);

    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only");
    var rows = keyed.readAfter(0, 100);
    String prev = AuditChain.GENESIS;
    for (var r : rows) {
      var forged = AuditChain.unkeyed().linkEvent(r, prev);
      sql(
          "UPDATE agentguard_audit SET chain_version = '"
              + forged.version()
              + "', prev_hash = '"
              + forged.prevHash()
              + "', hash = '"
              + forged.hash()
              + "' WHERE seq = "
              + r.sequence());
      prev = forged.hash();
    }
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER agentguard_audit_append_only");

    var report = AuditChainVerifier.of(keyed, keyedChain()).verify();

    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(report.brokenAtSequence()).isEqualTo(1L);
  }

  /**
   * Replaces the second half of the old F3 probe (F3(a), independent of the keyed-from-birth
   * migration and still owed). Nothing previously refused {@code DELETE}/{@code TRUNCATE} on {@code
   * agentguard_audit_anchor}; now the same append-only trigger pattern used on {@code
   * agentguard_audit} applies to the anchor table too.
   */
  @Test
  void anchor_delete_and_truncate_are_refused() throws Exception {
    var keyed = new JdbcAuditSink(ds, keyedChain());
    keyed.append(event(1));

    assertThatThrownBy(() -> sql("DELETE FROM agentguard_audit_anchor"))
        .hasMessageContaining("append-only");
    assertThatThrownBy(() -> sql("TRUNCATE agentguard_audit_anchor"))
        .hasMessageContaining("append-only");
    assertThat(query("SELECT count(*)::text FROM agentguard_audit_anchor")).containsExactly("1");

    // with the anchor still intact, a whole-trail downgrade is still caught (regression: F3(a)
    // does not weaken the F3 case above by making the anchor easier to lose)
    sql("ALTER TABLE agentguard_audit DISABLE TRIGGER agentguard_audit_append_only");
    sql(
        "UPDATE agentguard_audit SET chain_version = 'ag1', prev_hash = '"
            + AuditChain.GENESIS
            + "', hash = '"
            + AuditChain.unkeyed().hashOfEvent(keyed.readAfter(0, 1).get(0), AuditChain.GENESIS)
            + "' WHERE seq = 1");
    sql("ALTER TABLE agentguard_audit ENABLE TRIGGER agentguard_audit_append_only");
    assertThat(AuditChainVerifier.of(keyed, keyedChain()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.BROKEN);
  }

  /**
   * F3(a) also required by the review: a verifier given a key must never silently fall back to an
   * unanchored check. A reader that is not an {@code AuditAnchor} at all (the same rows, wrapped so
   * the anchor is invisible) reports {@code NO_ANCHOR}, never {@code INTACT}.
   */
  @Test
  void a_key_given_with_no_anchor_reader_reports_no_anchor_never_intact() throws Exception {
    var keyed = new JdbcAuditSink(ds, keyedChain());
    keyed.append(event(1));
    keyed.append(event(2));

    var noAnchor =
        new com.housedevinci.agentguard.domain.AuditReader() {
          @Override
          public List<AuditEvent> readAfter(long afterSequence, int limit) {
            return keyed.readAfter(afterSequence, limit);
          }

          @Override
          public List<AuditEvent> latest(String tenantId, int limit) {
            return keyed.latest(tenantId, limit);
          }
        };
    var report = AuditChainVerifier.of(noAnchor, keyedChain()).verify();

    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.NO_ANCHOR);
    assertThat(report.intact()).isFalse();
  }

  /**
   * Amendment (Dollar, after Cipher's design review): superseded version of the schema-seed test.
   * The schema step never re-seeds an anchor from an existing, non-empty trail — deriving {@code
   * keyed} from row data is exactly the guess the anchor exists to make unnecessary, the same class
   * of gap the retired {@code keyed_from_seq} F1/F2 findings were about. A keyed trail that loses
   * its anchor row is refused, not silently re-anchored: {@code AG-AUDIT-002}, naming the remedy.
   */
  @Test
  void an_orphaned_keyed_trail_without_an_anchor_refuses_to_append() throws Exception {
    var keyed = new JdbcAuditSink(ds, keyedChain());
    keyed.append(event(1));
    keyed.append(event(2));

    sql("ALTER TABLE agentguard_audit_anchor DISABLE TRIGGER ALL");
    sql("DELETE FROM agentguard_audit_anchor");
    sql("ALTER TABLE agentguard_audit_anchor ENABLE TRIGGER ALL");
    JdbcSupport.initializeSchema(ds); // does not resurrect the anchor: the trail is not empty

    assertThat(query("SELECT count(*) FROM agentguard_audit_anchor")).containsExactly("0");

    assertThatThrownBy(() -> keyed.append(event(3)))
        .isInstanceOf(AgentGuardException.class)
        .hasMessageContaining("start a new trail")
        .extracting(e -> ((AgentGuardException) e).code())
        .isEqualTo(ErrorCodes.AUDIT_ANCHOR_MISSING);
    assertThatThrownBy(() -> new JdbcAuditSink(ds, keyedChain()))
        .isInstanceOf(AgentGuardException.class)
        .extracting(e -> ((AgentGuardException) e).code())
        .isEqualTo(ErrorCodes.AUDIT_ANCHOR_MISSING);

    assertThat(AuditChainVerifier.of(keyed, keyedChain()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.NO_ANCHOR);
  }

  private static AuditChain keyedChain(String keyId) {
    var key = new byte[32];
    Arrays.fill(key, (byte) 7);
    return AuditChain.keyed(key, keyId);
  }

  /**
   * Key rotation (amendment, after Cipher's design review): the key id is part of the hashed
   * material from row 1, so a trail can carry rows signed under different ids while staying keyed
   * throughout — this is data, not a mode switch. A verifier whose keyring holds both ids sees the
   * whole trail INTACT.
   */
  @Test
  void mixed_key_rows_verify_intact_with_both_keys_in_the_keyring() throws Exception {
    var k1 = keyedChain("k1");
    var k2 = keyedChain("k2");
    var first = new JdbcAuditSink(ds, k1);
    first.append(event(1));
    // second instance, same trail, rotated to a different key id — allowed: the trail is still
    // keyed, only the signing id changed
    var second = new JdbcAuditSink(ds, k2);
    second.append(event(2));

    assertThat(query("SELECT key_id FROM agentguard_audit ORDER BY seq"))
        .containsExactly("k1", "k2");

    // both chains use the same 32 x 7 bytes in this probe; a real rotation would use different
    // secrets per id, which is exactly what the id makes possible without a format change
    var secretK1 = new byte[32];
    Arrays.fill(secretK1, (byte) 7);
    var fullKeyring = java.util.Map.of("k1", secretK1, "k2", secretK1);

    var report = AuditChainVerifier.of(second, fullKeyring).verify();

    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.INTACT);
    assertThat(report.keyIds()).containsExactlyInAnyOrder("k1", "k2");
    assertThat(report.keyed()).isTrue();
  }

  /**
   * A row claiming a key id the verifier's keyring does not hold is BROKEN, not skipped or treated
   * as unkeyed.
   */
  @Test
  void an_unknown_key_id_is_broken() throws Exception {
    var k1 = keyedChain("k1");
    var sink = new JdbcAuditSink(ds, k1);
    sink.append(event(1));

    // the verifier only knows about a different id ("k9"), not "k1"
    var secretK9 = new byte[32];
    Arrays.fill(secretK9, (byte) 9);
    var report = AuditChainVerifier.of(sink, java.util.Map.of("k9", secretK9)).verify();

    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(report.brokenAtSequence()).isEqualTo(1L);
  }

  /**
   * A stale-key second instance during a rotation: both instances are keyed (so the append-time
   * mismatch check does not fire — this is not a keyed-vs-unkeyed mismatch), but the second one
   * still has the old key id configured. Its append succeeds (each instance signs with its own
   * configured id); verifying with the full keyring is INTACT, verifying with only the new key is
   * BROKEN at the old instance's row.
   */
  @Test
  void a_stale_key_second_instance_appends_but_only_verifies_with_its_own_id_in_the_keyring()
      throws Exception {
    var oldId = keyedChain("k1");
    var newId = keyedChain("k2");
    var restarted = new JdbcAuditSink(ds, newId); // first ever append: anchor.keyed := true, k2
    restarted.append(event(1));
    // an instance that has not picked up the rotated key id yet, still running with k1
    var stale = new JdbcAuditSink(ds, oldId); // keyed vs keyed: no mismatch, append accepted
    var staleRow = stale.append(event(2));
    assertThat(staleRow.keyId()).isEqualTo("k1");

    var secretK1 = new byte[32];
    Arrays.fill(secretK1, (byte) 7);
    var secretK2 = secretK1; // same bytes in this probe; distinct ids are what matters

    assertThat(
            AuditChainVerifier.of(restarted, java.util.Map.of("k1", secretK1, "k2", secretK2))
                .verify()
                .status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);

    var newKeyOnly = AuditChainVerifier.of(restarted, java.util.Map.of("k2", secretK2)).verify();
    assertThat(newKeyOnly.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(newKeyOnly.brokenAtSequence()).isEqualTo(staleRow.sequence());
  }

  /**
   * Attack that did not break: the trigger extension really does apply to a database created by an
   * earlier schema version. {@code CREATE OR REPLACE FUNCTION} rewrites the function body in place
   * and the existing trigger, which references it by oid, picks the new body up without being
   * recreated — so an upgraded installation gets {@code keyed} immutability, not just a fresh one.
   */
  @Test
  void confirms_the_extended_monotonic_trigger_applies_to_an_upgraded_database() throws Exception {
    // simulate a database created before the keyed column existed: the pre-migration function
    // body, no keyed clause
    sql(
        "CREATE OR REPLACE FUNCTION agentguard_audit_anchor_monotonic() RETURNS trigger AS $$\n"
            + "BEGIN\n"
            + "  IF NEW.row_count <> OLD.row_count + 1 OR NEW.head_hash = OLD.head_hash THEN\n"
            + "    RAISE EXCEPTION 'anchor only advances by one row';\n"
            + "  END IF;\n"
            + "  RETURN NEW;\n"
            + "END;\n"
            + "$$ LANGUAGE plpgsql");
    var keyed = new JdbcAuditSink(ds, keyedChain());
    keyed.append(event(1));
    // under the old body `keyed` is freely movable
    sql(
        "UPDATE agentguard_audit_anchor SET keyed = false, row_count = row_count + 1,"
            + " head_hash = '"
            + "b".repeat(64)
            + "' WHERE id = 1");
    assertThat(query("SELECT keyed::text FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("false");

    JdbcSupport.initializeSchema(ds); // the upgrade runs the new schema

    Throwable thrown = null;
    try {
      sql(
          "UPDATE agentguard_audit_anchor SET keyed = true, row_count = row_count + 1,"
              + " head_hash = '"
              + "c".repeat(64)
              + "' WHERE id = 1");
    } catch (SQLException e) {
      thrown = e;
    }
    assertThat(thrown).isNotNull();
    assertThat(thrown).hasMessageContaining("keyed is immutable once set");
  }

  /**
   * Attack that did not break: two sink instances racing to make the first keyed append. The
   * transaction-scoped advisory lock in {@code JdbcAuditSink.append} covers the read of the anchor,
   * the anchor upsert and the row INSERT as one unit, so every append agrees on {@code keyed} and
   * no interleaving produces an anchor the immutability trigger would reject.
   */
  @Test
  void confirms_concurrent_first_appends_agree_on_keyed_exactly_once() throws Exception {
    var a = new JdbcAuditSink(ds, keyedChain());
    var b = new JdbcAuditSink(ds, keyedChain());
    int n = 12;
    var start = new CountDownLatch(1);
    var done = new CountDownLatch(n);
    var failures = new ArrayList<Throwable>();
    try (var pool = Executors.newFixedThreadPool(n)) {
      for (int i = 0; i < n; i++) {
        int idx = i;
        pool.submit(
            () -> {
              try {
                start.await();
                (idx % 2 == 0 ? a : b).append(event(100 + idx));
              } catch (Throwable t) {
                synchronized (failures) {
                  failures.add(t);
                }
              } finally {
                done.countDown();
              }
            });
      }
      start.countDown();
      assertThat(done.await(60, TimeUnit.SECONDS)).isTrue();
    }

    assertThat(failures).isEmpty();
    assertThat(query("SELECT count(*) FROM agentguard_audit")).containsExactly(String.valueOf(n));
    assertThat(query("SELECT keyed::text FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("true");
    assertThat(AuditChainVerifier.of(a, keyedChain()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
  }

  /**
   * Pins the residual: a role holding exactly the documented runtime grant (docs, "Database roles":
   * {@code SELECT, INSERT} on {@code agentguard_audit}, {@code SELECT, INSERT, UPDATE} on {@code
   * agentguard_audit_anchor}, no DDL, not the owner) cannot delete the anchor row, replace the
   * monotonic trigger's function, or disable triggers. Only the table owner can.
   */
  @Test
  void confirms_the_documented_runtime_role_cannot_delete_the_anchor_or_touch_the_trigger()
      throws Exception {
    sql("DROP ROLE IF EXISTS agentguard_runtime_probe");
    sql("CREATE ROLE agentguard_runtime_probe LOGIN PASSWORD 'probe'");
    sql("GRANT USAGE ON SCHEMA public TO agentguard_runtime_probe");
    sql("GRANT SELECT, INSERT ON agentguard_audit TO agentguard_runtime_probe");
    sql("GRANT SELECT, INSERT, UPDATE ON agentguard_audit_anchor TO agentguard_runtime_probe");
    sql("GRANT USAGE ON SEQUENCE agentguard_audit_seq_seq TO agentguard_runtime_probe");

    var runtime = new HikariDataSource();
    runtime.setJdbcUrl(POSTGRES.getJdbcUrl());
    runtime.setUsername("agentguard_runtime_probe");
    runtime.setPassword("probe");
    runtime.setMaximumPoolSize(2);
    try (runtime) {
      assertThat(runtimeFails(runtime, "DELETE FROM agentguard_audit_anchor"))
          .contains("permission denied");
      assertThat(
              runtimeFails(
                  runtime,
                  "CREATE OR REPLACE FUNCTION agentguard_audit_anchor_monotonic() RETURNS trigger"
                      + " AS $$ BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql"))
          .isNotNull();
      assertThat(runtimeFails(runtime, "ALTER TABLE agentguard_audit DISABLE TRIGGER ALL"))
          .isNotNull();
      assertThat(runtimeFails(runtime, "ALTER TABLE agentguard_audit_anchor DISABLE TRIGGER ALL"))
          .isNotNull();
    } finally {
      sql("REVOKE ALL ON agentguard_audit, agentguard_audit_anchor FROM agentguard_runtime_probe");
      sql("REVOKE ALL ON SEQUENCE agentguard_audit_seq_seq FROM agentguard_runtime_probe");
      sql("REVOKE USAGE ON SCHEMA public FROM agentguard_runtime_probe");
      sql("DROP ROLE IF EXISTS agentguard_runtime_probe");
    }
  }

  private static String runtimeFails(HikariDataSource runtime, String statement) {
    try (var c = runtime.getConnection();
        Statement st = c.createStatement()) {
      st.execute(statement);
      return null;
    } catch (SQLException e) {
      return e.getMessage();
    }
  }
}

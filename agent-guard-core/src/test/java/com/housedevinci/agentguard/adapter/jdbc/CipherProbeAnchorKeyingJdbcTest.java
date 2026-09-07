package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

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
 * Cipher final-verification probes against the V2 fix's new surface: {@code
 * agentguard_audit_anchor.keyed_from_seq} (QUESTIONS.md #20). The {@code probe_*} tests assert
 * today's — broken — behaviour so the suite stays green; Isis flips each assertion when the fix
 * lands. The {@code confirms_*} tests are attacks that did <em>not</em> break and are kept as
 * regression cover for the parts of V2 that hold.
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
   * F1 (MEDIUM). {@code JdbcAuditSink.append} sets {@code keyed_from_seq = count + 1} — the
   * anchor's row <em>count</em> plus one — but the column the verifier compares it against is
   * {@code agentguard_audit.seq}, a {@code bigserial}. The two diverge the moment the sequence has
   * a gap, and a gap is left behind by any rolled-back INSERT: a role holding nothing but the
   * documented runtime grant ({@code SELECT, INSERT} on {@code agentguard_audit}) can burn sequence
   * values at will, and an ordinary failed append does it by accident. The keyed transition is then
   * recorded at a sequence belonging to an older, legitimately unkeyed row, and the verifier
   * reports BROKEN on a trail nobody touched — permanently, because the extended monotonic trigger
   * makes {@code keyed_from_seq} immutable once set.
   *
   * <p>Fix: record the appended row's real sequence. Do the INSERT ... RETURNING seq first, then
   * write the anchor with that seq in the same transaction (the advisory lock already serialises
   * appends), instead of deriving it from {@code row_count}. Test: this probe, asserting
   * {@code INTACT}.
   */
  @Test
  void probe_a_bigserial_gap_makes_an_untampered_keyed_trail_report_broken() throws Exception {
    var unkeyed = new JdbcAuditSink(ds);
    unkeyed.append(event(1));
    unkeyed.append(event(2));
    // an append that rolls back burns a sequence value; the trail now has a gap
    try (var c = ds.getConnection()) {
      c.setAutoCommit(false);
      try (Statement st = c.createStatement()) {
        st.execute(
            "INSERT INTO agentguard_audit (ts, principal_id, tool, args_hash, decision, prev_hash,"
                + " hash) VALUES (now(), 'x', 't', '"
                + "a".repeat(64)
                + "', 'ALLOWED', '"
                + "0".repeat(64)
                + "', '"
                + "f".repeat(64)
                + "')");
      }
      c.rollback();
    }
    var third = unkeyed.append(event(3));
    assertThat(third.sequence()).isEqualTo(4L); // seq 3 was burned; row_count is 3

    var keyed = new JdbcAuditSink(ds, keyedChain());
    var first = keyed.append(event(4)); // first keyed append: keyed_from_seq := row_count + 1 = 4
    assertThat(first.sequence()).isEqualTo(5L);

    assertThat(query("SELECT keyed_from_seq FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("4"); // ...but seq 4 is the unkeyed row appended above

    var report = AuditChainVerifier.of(keyed, keyedChain()).verify();

    // nothing was tampered with, yet:
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(report.brokenAtSequence()).isEqualTo(4L);
  }

  /**
   * F2 (MEDIUM). The schema step's anchor seed ({@code INSERT INTO agentguard_audit_anchor (id,
   * head_hash, row_count, updated_at) SELECT …}) does not derive {@code keyed_from_seq} from the
   * trail, unlike {@code JdbcAuditSink.append}'s own re-derivation for a missing anchor. Startup
   * runs the schema step before any append, so on an installation whose anchor row was lost the
   * seed wins the race and the sink's re-derivation never runs: a genuinely keyed trail comes back
   * with {@code keyed_from_seq} NULL and every row claiming {@code ag2h}, which the V2 rule reports
   * BROKEN. The next append then sets {@code keyed_from_seq} to the wrong (current) sequence and
   * the trigger freezes that mistake in place.
   *
   * <p>Fix: derive it in the seed too — {@code (SELECT min(seq) FROM agentguard_audit WHERE
   * chain_version = 'ag2h')} as the seeded {@code keyed_from_seq}, matching the sink. Test: this
   * probe, asserting {@code INTACT}.
   */
  @Test
  void probe_the_schema_anchor_seed_forgets_keyed_from_seq_and_breaks_a_keyed_trail()
      throws Exception {
    var keyed = new JdbcAuditSink(ds, keyedChain());
    keyed.append(event(1));
    keyed.append(event(2));
    assertThat(query("SELECT keyed_from_seq FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("1");
    assertThat(AuditChainVerifier.of(keyed, keyedChain()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);

    // the anchor row is lost (a restore from a dump taken before the anchor existed, an operator
    // clearing it — the "pre-anchor installation" both the code and the schema anticipate)
    sql("DELETE FROM agentguard_audit_anchor");
    JdbcSupport.initializeSchema(ds); // the startup schema step re-seeds it

    assertThat(query("SELECT keyed_from_seq FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly((String) null); // seeded, but with no keying record

    var report = AuditChainVerifier.of(keyed, keyedChain()).verify();

    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(report.brokenAtSequence()).isEqualTo(1L);
  }

  /**
   * F3 (MEDIUM). The anchor's monotonic trigger is {@code BEFORE UPDATE} only — nothing refuses
   * {@code DELETE} on {@code agentguard_audit_anchor}, where {@code agentguard_audit} has both a
   * row trigger and a TRUNCATE trigger. With the anchor row gone {@code AuditChainVerifier} finds
   * no anchor, drops back to the in-trail {@code keyedSeen} rule <em>silently</em> — no distinct
   * status, no log, no field on the report — and the whole-trail downgrade reports INTACT again:
   * exactly the V2 result the fix was meant to close. The head-hash/row-count check disappears with
   * it, so tail deletion is undetectable in the same breath. DELETE is outside the documented
   * runtime grant, so this is the table owner's residual — but the report gives an operator no way
   * to tell an anchored verification from an unanchored one.
   *
   * <p>Fix: two parts. (a) Refuse DELETE and TRUNCATE on {@code agentguard_audit_anchor} with the
   * same trigger pattern used on {@code agentguard_audit}. (b) Make the fallback loud: a distinct
   * {@code Status.NO_ANCHOR} (or an {@code anchored} flag on {@code Report}) when {@code
   * anchor.anchor()} is empty and the reader implements {@code AuditAnchor}, so an unanchored
   * verification never renders as INTACT. Test: this probe, asserting the new status.
   */
  @Test
  void probe_deleting_the_anchor_row_restores_the_whole_trail_downgrade_to_intact()
      throws Exception {
    var keyed = new JdbcAuditSink(ds, keyedChain());
    keyed.append(event(1));
    keyed.append(event(2));

    // the attacker relinks every row unkeyed from GENESIS and stamps chain_version 'ag1'
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

    // with the anchor intact the downgrade is caught (the V2 fix, working)
    assertThat(AuditChainVerifier.of(keyed, keyedChain()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.BROKEN);

    // no trigger refuses DELETE on the anchor
    sql("DELETE FROM agentguard_audit_anchor");

    var report = AuditChainVerifier.of(keyed, keyedChain()).verify();

    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.INTACT);
    assertThat(report.verified()).isEqualTo(2L);
  }

  /**
   * F4 (LOW). {@code keyed_from_seq} is set by whichever instance happens to make the first keyed
   * append, but nothing stops an instance that is still unkeyed from appending after it — which is
   * exactly what a rolling restart does while {@code agentguard.audit.hmac-secret} is being rolled
   * out. One unkeyed row lands after {@code keyed_from_seq} and the trail is permanently BROKEN:
   * the row cannot be removed (append-only) and {@code keyed_from_seq} cannot be moved (immutable).
   * The documented migration story ("enabling the HMAC key is a one-way step, safely") does not
   * mention that the step must be atomic across instances.
   *
   * <p>Fix: the sink refuses to append unkeyed when the anchor already carries a non-null {@code
   * keyed_from_seq} (fail closed on the misconfigured instance rather than corrupting the trail),
   * and the docs state that enabling the secret requires a full stop-start, not a rolling restart.
   * Test: this probe, asserting the unkeyed append throws.
   */
  @Test
  void probe_an_unkeyed_instance_appending_after_the_keying_point_breaks_the_trail_forever()
      throws Exception {
    var oldInstance = new JdbcAuditSink(ds); // still without the secret
    var newInstance = new JdbcAuditSink(ds, keyedChain()); // restarted with the secret
    oldInstance.append(event(1));
    newInstance.append(event(2)); // keyed_from_seq := 2
    assertThat(query("SELECT keyed_from_seq FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("2");

    // the not-yet-restarted instance keeps serving traffic and appends unkeyed
    oldInstance.append(event(3));

    var report = AuditChainVerifier.of(newInstance, keyedChain()).verify();

    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.BROKEN);
    assertThat(report.brokenAtSequence()).isEqualTo(3L);
  }

  /**
   * Attack that did not break: the V2 trigger extension really does apply to a database created by
   * an earlier version of the schema. {@code CREATE OR REPLACE FUNCTION} rewrites the function body
   * in place and the existing trigger, which references it by oid, picks the new body up without
   * being recreated — so an upgraded installation gets {@code keyed_from_seq} immutability, not
   * just a fresh one. Replacing the function needs ownership, which the documented runtime role
   * does not have.
   */
  @Test
  void confirms_the_extended_monotonic_trigger_applies_to_an_upgraded_database() throws Exception {
    // simulate a database created before V2: the pre-V2 function body, no keyed_from_seq clause
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
    // under the old body keyed_from_seq is freely movable
    sql(
        "UPDATE agentguard_audit_anchor SET keyed_from_seq = 99, row_count = row_count + 1,"
            + " head_hash = '"
            + "b".repeat(64)
            + "' WHERE id = 1");
    assertThat(query("SELECT keyed_from_seq FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("99");

    JdbcSupport.initializeSchema(ds); // the upgrade runs the new schema

    Throwable thrown = null;
    try {
      sql(
          "UPDATE agentguard_audit_anchor SET keyed_from_seq = 1, row_count = row_count + 1,"
              + " head_hash = '"
              + "c".repeat(64)
              + "' WHERE id = 1");
    } catch (SQLException e) {
      thrown = e;
    }
    assertThat(thrown).isNotNull();
    assertThat(thrown).hasMessageContaining("keyed_from_seq is immutable once set");
  }

  /**
   * Attack that did not break: two sink instances racing to make the first keyed append. The
   * transaction-scoped advisory lock in {@code JdbcAuditSink.append} covers the read of {@code
   * keyed_from_seq}, the anchor upsert and the row INSERT as one unit, so exactly one of them sets
   * it, the value is the lowest keyed sequence, and no interleaving produces a second write that
   * the immutability trigger would reject.
   */
  @Test
  void confirms_concurrent_first_keyed_appends_set_keyed_from_seq_exactly_once() throws Exception {
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
    assertThat(query("SELECT keyed_from_seq FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("1");
    assertThat(query("SELECT min(seq)::text FROM agentguard_audit WHERE chain_version = 'ag2h'"))
        .containsExactly("1");
    assertThat(AuditChainVerifier.of(a, keyedChain()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
  }

  /**
   * Attack that pins the two findings above to the right severity: a role holding exactly the
   * documented runtime grant (docs, "Database roles": {@code SELECT, INSERT} on {@code
   * agentguard_audit}, {@code SELECT, INSERT, UPDATE} on {@code agentguard_audit_anchor}, no DDL,
   * not the owner). It cannot replace the monotonic trigger's function and cannot delete the anchor
   * row — so F3 stays the table owner's documented residual — but it <em>can</em> burn sequence
   * values with a rolled-back INSERT, which is all F1 needs.
   */
  @Test
  void confirms_the_documented_runtime_role_can_burn_sequence_values_but_not_touch_the_trigger()
      throws Exception {
    sql("DROP ROLE IF EXISTS agentguard_runtime_probe");
    sql("CREATE ROLE agentguard_runtime_probe LOGIN PASSWORD 'probe'");
    sql("GRANT USAGE ON SCHEMA public TO agentguard_runtime_probe");
    sql("GRANT SELECT, INSERT ON agentguard_audit TO agentguard_runtime_probe");
    sql(
        "GRANT SELECT, INSERT, UPDATE ON agentguard_audit_anchor TO agentguard_runtime_probe");
    sql(
        "GRANT USAGE ON SEQUENCE agentguard_audit_seq_seq TO agentguard_runtime_probe");

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

      // but nothing stops it burning sequence values with an INSERT it then rolls back
      var appended = new JdbcAuditSink(ds).append(event(1));
      assertThat(appended.sequence()).isEqualTo(1L);
      try (var c = runtime.getConnection()) {
        c.setAutoCommit(false);
        for (int i = 0; i < 3; i++) {
          try (Statement st = c.createStatement()) {
            st.execute(
                "INSERT INTO agentguard_audit (ts, principal_id, tool, args_hash, decision,"
                    + " prev_hash, hash) VALUES (now(), 'x', 't', '"
                    + "a".repeat(64)
                    + "', 'ALLOWED', '"
                    + "0".repeat(64)
                    + "', '"
                    + Integer.toString(i).repeat(64)
                    + "')");
          }
        }
        c.rollback();
      }
      // the next genuine append lands three sequence values further on than its row number
      var next = new JdbcAuditSink(ds).append(event(2));
      assertThat(next.sequence()).isEqualTo(5L);
      assertThat(query("SELECT row_count::text FROM agentguard_audit_anchor WHERE id = 1"))
          .containsExactly("2");
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

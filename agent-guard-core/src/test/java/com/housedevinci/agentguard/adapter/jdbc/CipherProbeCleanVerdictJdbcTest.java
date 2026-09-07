package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Cipher clean-verdict pass on f27c45e. Temporary. */
@Testcontainers
class CipherProbeCleanVerdictJdbcTest {

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
    ds.setMaximumPoolSize(12);
  }

  @AfterAll
  static void close() {
    ds.close();
  }

  @BeforeEach
  void fresh() throws SQLException {
    sql("DROP SCHEMA IF EXISTS oldcopy CASCADE");
    sql("DROP TABLE IF EXISTS agentguard_audit_anchor");
    sql("DROP TABLE IF EXISTS agentguard_audit");
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

  private static AuditEvent event(int i) {
    return AuditEvent.builder()
        .timestamp(Instant.parse("2026-09-08T10:00:00Z").plusSeconds(i))
        .principalId("u1")
        .tool("t")
        .argsHash("a".repeat(64))
        .decision(AuditDecision.ALLOWED)
        .correlationId("c" + i)
        .build();
  }

  private static byte[] key(int b) {
    var k = new byte[32];
    Arrays.fill(k, (byte) b);
    return k;
  }

  /** G1/G2: three runs on a database created by this version, empty and then non-empty. */
  @Test
  void probe_schema_step_is_idempotent_three_times_empty_and_non_empty() throws Exception {
    JdbcSupport.initializeSchema(ds);
    JdbcSupport.initializeSchema(ds);
    JdbcSupport.initializeSchema(ds);
    assertThat(query("SELECT count(*)::text FROM agentguard_audit")).containsExactly("0");

    var sink = new JdbcAuditSink(ds, AuditChain.keyed(key(1), "k1"));
    sink.append(event(1));
    sink.append(event(2));
    String head = query("SELECT head_hash FROM agentguard_audit_anchor WHERE id = 1").get(0);

    JdbcSupport.initializeSchema(ds);
    JdbcSupport.initializeSchema(ds);
    JdbcSupport.initializeSchema(ds);

    assertThat(query("SELECT count(*)::text FROM agentguard_audit")).containsExactly("2");
    assertThat(query("SELECT head_hash FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly(head);
    assertThat(query("SELECT keyed::text FROM agentguard_audit_anchor WHERE id = 1"))
        .containsExactly("true");
  }

  /** G1/G2: twelve concurrent starts on an empty database, under the advisory lock. */
  @Test
  void probe_concurrent_schema_steps_on_an_empty_database_all_succeed() throws Exception {
    int n = 12;
    var start = new CountDownLatch(1);
    var done = new CountDownLatch(n);
    var failure = new AtomicReference<Throwable>();
    try (var pool = Executors.newFixedThreadPool(n)) {
      for (int i = 0; i < n; i++) {
        pool.submit(
            () -> {
              try {
                start.await();
                JdbcSupport.initializeSchema(ds);
              } catch (Throwable t) {
                failure.compareAndSet(null, t);
              } finally {
                done.countDown();
              }
            });
      }
      start.countDown();
      assertThat(done.await(120, TimeUnit.SECONDS)).isTrue();
    }
    assertThat(failure.get()).isNull();
    assertThat(query("SELECT count(*)::text FROM agentguard_audit")).containsExactly("0");
    var sink = new JdbcAuditSink(ds, AuditChain.keyed(key(1), "k1"));
    sink.append(event(1));
    assertThat(query("SELECT count(*)::text FROM agentguard_audit")).containsExactly("1");
  }

  /** G1/G2: the predates guard cannot be tripped by a fresh, empty database. */
  @Test
  void probe_a_fresh_empty_database_never_trips_the_predates_guard() {
    assertThatCode(() -> JdbcSupport.initializeSchema(ds)).doesNotThrowAnyException();
  }

  /** The refusal message must not suggest an in-place upgrade. */
  @Test
  void probe_the_predates_message_offers_no_in_place_upgrade() throws Exception {
    JdbcSupport.initializeSchema(ds);
    sql("ALTER TABLE agentguard_audit DROP COLUMN key_id");
    assertThatThrownBy(() -> JdbcSupport.initializeSchema(ds))
        .satisfies(
            t -> {
              String m = t.getMessage().toLowerCase(java.util.Locale.ROOT);
              assertThat(m).contains("archive the table and start a new trail");
              assertThat(m).doesNotContain("upgrade");
              assertThat(m).doesNotContain("migrate");
              assertThat(m).doesNotContain("add column");
              assertThat(m).doesNotContain("backfill");
            });
  }

  /**
   * J1 (fixed). The predates guard now resolves the table via {@code to_regclass}, search_path-
   * relative like every other statement in the step, and checks the column against that same oid
   * via {@code pg_attribute}: a pre-redesign copy of the table in ANOTHER schema the role can see
   * no longer blocks a fresh install in the current one.
   */
  @Test
  void probe_a_pre_redesign_table_in_another_schema_blocks_a_fresh_install() throws Exception {
    sql("CREATE SCHEMA oldcopy");
    sql("CREATE TABLE oldcopy.agentguard_audit (seq bigserial PRIMARY KEY, hash char(64))");
    assertThatCode(() -> JdbcSupport.initializeSchema(ds)).doesNotThrowAnyException();
  }
}

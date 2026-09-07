package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** the security review final-pass probe: anchor seeding when several instances start (and append) at once. */
@Testcontainers
class CipherProbeFinalJdbcTest {

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
    ds.setMaximumPoolSize(16);
  }

  @AfterAll
  static void close() {
    ds.close();
  }

  private static AuditEvent event(int i) {
    return AuditEvent.builder()
        .timestamp(Instant.parse("2026-09-06T10:00:00Z").plusSeconds(i))
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

  /**
   * Amendment note (the maintainers, after the security review's design review): this probe used to delete the anchor row
   * on a non-empty trail to model "a pre-anchor installation" and expect the schema step and the
   * sink to re-anchor it consistently under concurrent load. Under keyed-from-birth that premise no
   * longer holds — a missing anchor on a non-empty trail is refused (AG-AUDIT-002), not re-derived
   * — so this probe now keeps the anchor intact throughout and exercises the still-valid part: many
   * instances starting (schema step) and appending concurrently on an already-anchored trail never
   * abort each other (R11).
   */
  @Test
  void concurrent_first_starts_and_appends_never_abort_each_other_on_an_anchored_trail()
      throws Exception {
    JdbcSupport.initializeSchema(ds);
    var sink = new JdbcAuditSink(ds);
    for (int i = 0; i < 5; i++) {
      sink.append(event(i));
    }
    var pool = Executors.newFixedThreadPool(12);
    try {
      var go = new CountDownLatch(1);
      List<Future<String>> results = new ArrayList<>();
      for (int i = 0; i < 8; i++) {
        results.add(
            pool.submit(
                () -> {
                  go.await();
                  try {
                    JdbcSupport.initializeSchema(ds); // eight instances starting together
                    return "ok";
                  } catch (RuntimeException e) {
                    return "schema: " + e.getMessage();
                  }
                }));
      }
      for (int i = 0; i < 4; i++) {
        int n = 100 + i;
        results.add(
            pool.submit(
                () -> {
                  go.await();
                  try {
                    sink.append(event(n)); // and traffic arriving on an already-started instance
                    return "ok";
                  } catch (RuntimeException e) {
                    return "append: " + e.getMessage();
                  }
                }));
      }
      go.countDown();
      var outcomes = new ArrayList<String>();
      for (var f : results) {
        outcomes.add(f.get());
      }
      System.out.println("outcomes: " + outcomes);
      var report = new AuditChainVerifier(sink).verify();
      System.out.println("report: " + report + " anchor: " + sink.anchor());
      // invariant: whatever the race did, trail and anchor agree and the chain verifies
      assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.INTACT_UNKEYED);
      assertThat(sink.anchor().orElseThrow().rowCount()).isEqualTo(report.verified());
      // R11 flipped: schema runs take the sink's advisory lock first and only create what is
      // absent, so neither a startup nor an append is ever aborted
      assertThat(outcomes).containsOnly("ok");
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void concurrent_first_starts_on_an_empty_database() throws Exception {
    sql(
        "DROP TABLE IF EXISTS agentguard_audit_anchor, agentguard_audit, agentguard_decision, agentguard_budget CASCADE");
    sql("DROP FUNCTION IF EXISTS agentguard_audit_append_only() CASCADE");
    var pool = Executors.newFixedThreadPool(8);
    try {
      var go = new CountDownLatch(1);
      List<Future<String>> results = new ArrayList<>();
      for (int i = 0; i < 8; i++) {
        results.add(
            pool.submit(
                () -> {
                  go.await();
                  try {
                    JdbcSupport.initializeSchema(ds);
                    return "ok";
                  } catch (RuntimeException e) {
                    return "schema: " + e.getMessage();
                  }
                }));
      }
      go.countDown();
      var outcomes = new ArrayList<String>();
      for (var f : results) {
        outcomes.add(f.get());
      }
      System.out.println("empty-db outcomes: " + outcomes);
      // R11 flipped: eight first starts on an empty database all succeed
      assertThat(outcomes).containsOnly("ok");
      // whatever the race printed, the schema must be usable afterwards
      JdbcSupport.initializeSchema(ds);
      var sink = new JdbcAuditSink(ds);
      sink.append(event(1));
      assertThat(new AuditChainVerifier(sink).verify().status())
          .isEqualTo(AuditChainVerifier.Status.INTACT_UNKEYED);
    } finally {
      pool.shutdownNow();
    }
  }
}

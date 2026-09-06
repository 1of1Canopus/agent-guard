package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolRef;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class JdbcAdaptersIntegrationTest {

  @Container
  static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

  static HikariDataSource ds;

  @BeforeAll
  static void schema() {
    ds = new HikariDataSource();
    ds.setJdbcUrl(POSTGRES.getJdbcUrl());
    ds.setUsername(POSTGRES.getUsername());
    ds.setPassword(POSTGRES.getPassword());
    ds.setMaximumPoolSize(16);
    JdbcSupport.initializeSchema(ds);
    JdbcSupport.initializeSchema(ds); // idempotent
  }

  @AfterAll
  static void close() {
    ds.close();
  }

  private static final Principal P =
      new Principal("u1", Set.of("AGENT", "OPS"), Set.of("s1"), "acme");

  private static PendingDecision decision(String args) {
    var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
    return PendingDecision.park(
        P,
        new ToolRef("write", SideEffect.WRITE),
        args,
        "preview",
        "conv",
        "corr",
        now,
        now.plus(Duration.ofHours(1)));
  }

  @Test
  void decision_round_trip_and_lookups() {
    var store = new JdbcDecisionStore(ds);
    var d = decision("{\"a\":1}");
    store.save(d);
    assertThat(store.findById(d.id())).contains(d);
    assertThat(store.findLatest("u1", "write", d.argsHash())).contains(d);
    assertThat(store.findByState(DecisionState.PENDING, 100)).contains(d);
    assertThat(store.findById(d.id()).orElseThrow().principal().roles())
        .containsExactlyInAnyOrder("AGENT", "OPS");
  }

  @Test
  void transition_is_compare_and_set() {
    var store = new JdbcDecisionStore(ds);
    var d = decision("{\"a\":2}");
    store.save(d);
    var at = Instant.now().truncatedTo(ChronoUnit.MILLIS);
    assertThat(store.transition(d.id(), DecisionState.PENDING, DecisionState.APPROVED, "alice", at))
        .isTrue();
    assertThat(store.transition(d.id(), DecisionState.PENDING, DecisionState.REJECTED, "bob", at))
        .isFalse();
    var loaded = store.findById(d.id()).orElseThrow();
    assertThat(loaded.state()).isEqualTo(DecisionState.APPROVED);
    assertThat(loaded.decidedBy()).isEqualTo("alice");
    assertThat(loaded.decidedAt()).isEqualTo(at);
  }

  @Test
  void mark_executed_once_wins_exactly_once_under_concurrency() throws Exception {
    var store = new JdbcDecisionStore(ds);
    var d = decision("{\"a\":3}");
    store.save(d);
    int winners = 0;
    try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
      var futures = new ArrayList<Future<Boolean>>();
      for (int i = 0; i < 50; i++) {
        futures.add(pool.submit(() -> store.markExecutedOnce(d.id())));
      }
      for (var f : futures) {
        if (f.get()) {
          winners++;
        }
      }
    }
    assertThat(winners).isEqualTo(1);
    store.storeResult(d.id(), "{\"done\":true}");
    assertThat(store.findById(d.id()).orElseThrow().result()).contains("{\"done\":true}");
  }

  @Test
  void audit_chain_is_linear_under_concurrent_appends_and_verifies() throws Exception {
    var sink = new JdbcAuditSink(ds);
    try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
      var futures = new ArrayList<Future<AuditEvent>>();
      for (int i = 0; i < 100; i++) {
        final int n = i;
        futures.add(pool.submit(() -> sink.append(event("t" + n))));
      }
      for (var f : futures) {
        assertThat(f.get().sequence()).isPositive();
      }
    }
    var report = new AuditChainVerifier(sink).verify();
    assertThat(report.intact()).isTrue();
    assertThat(report.verified()).isGreaterThanOrEqualTo(100);
    assertThat(sink.latest(5)).hasSize(5);
    assertThat(sink.latest(1).get(0).sequence()).isEqualTo(report.verified());
  }

  @Test
  void audit_table_refuses_update_and_delete() {
    var sink = new JdbcAuditSink(ds);
    var e = sink.append(event("immutable"));
    assertThatThrownBy(
            () ->
                JdbcSupport.withConnection(
                    ds,
                    c -> {
                      try (var st = c.createStatement()) {
                        return st.executeUpdate(
                            "UPDATE agentguard_audit SET tool = 'x' WHERE seq = " + e.sequence());
                      }
                    }))
        .hasCauseInstanceOf(SQLException.class)
        .hasMessageContaining("append-only");
    assertThatThrownBy(
            () ->
                JdbcSupport.withConnection(
                    ds,
                    c -> {
                      try (var st = c.createStatement()) {
                        return st.executeUpdate(
                            "DELETE FROM agentguard_audit WHERE seq = " + e.sequence());
                      }
                    }))
        .hasMessageContaining("append-only");
  }

  @Test
  void budget_counter_is_atomic_and_expires() throws Exception {
    var clock = new MutableClock(Instant.parse("2026-09-06T10:00:00Z"));
    var store = new JdbcBudgetStore(ds, clock);
    var key = "agentguard:budget:test:" + System.nanoTime();
    var ttl = Duration.ofMinutes(1);
    List<Long> seen = new ArrayList<>();
    try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
      var futures = new ArrayList<Future<Long>>();
      for (int i = 0; i < 100; i++) {
        futures.add(pool.submit(() -> store.incrementAndGet(key, 1, ttl)));
      }
      for (var f : futures) {
        seen.add(f.get());
      }
    }
    assertThat(seen).hasSize(100).doesNotHaveDuplicates().contains(1L, 100L);
    assertThat(store.current(key)).isEqualTo(100);
    clock.now = clock.now.plus(Duration.ofMinutes(2));
    assertThat(store.current(key)).isZero();
    assertThat(store.incrementAndGet(key, 5, ttl)).isEqualTo(5);
  }

  private static AuditEvent event(String tool) {
    return AuditEvent.builder()
        .timestamp(Instant.now().truncatedTo(ChronoUnit.MILLIS))
        .principalId("p")
        .tenantId("acme")
        .tool(tool)
        .argsHash("a")
        .resultHash("r")
        .latencyMillis(3)
        .decision(AuditDecision.ALLOWED)
        .correlationId("c")
        .build();
  }

  static final class MutableClock extends Clock {
    Instant now;

    MutableClock(Instant now) {
      this.now = now;
    }

    @Override
    public java.time.ZoneId getZone() {
      return java.time.ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}

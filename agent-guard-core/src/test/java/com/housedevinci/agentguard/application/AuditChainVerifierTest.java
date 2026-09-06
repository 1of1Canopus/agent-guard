package com.housedevinci.agentguard.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class AuditChainVerifierTest {

  private static AuditEvent event(String tool) {
    return AuditEvent.builder()
        .timestamp(Instant.EPOCH)
        .principalId("p")
        .tool(tool)
        .decision(AuditDecision.ALLOWED)
        .build();
  }

  @Test
  void empty_trail_is_intact() {
    var report = new AuditChainVerifier(new InMemoryAuditSink()).verify();
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.EMPTY);
    assertThat(report.intact()).isTrue();
  }

  @Test
  void detects_a_modified_row_in_the_middle() {
    var sink = new InMemoryAuditSink();
    for (int i = 0; i < 1200; i++) {
      sink.append(event("t" + i));
    }
    assertThat(new AuditChainVerifier(sink).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
    var row = sink.readAfter(599, 1).get(0);
    sink.tamper(599, row.withTool("evil"));
    var report = new AuditChainVerifier(sink).verify();
    assertThat(report.intact()).isFalse();
    assertThat(report.brokenAtSequence()).isEqualTo(600);
    assertThat(report.verified()).isEqualTo(599);
  }

  @Test
  void detects_a_deleted_row() {
    var sink = new InMemoryAuditSink();
    sink.append(event("a"));
    var b = sink.append(event("b"));
    sink.append(event("c"));
    // simulate deletion of "b" by replacing it with a relinked copy of c pointing at a
    sink.tamper(1, sink.readAfter(2, 1).get(0).withSequence(2));
    assertThat(new AuditChainVerifier(sink).verify().brokenAtSequence()).isEqualTo(2);
    assertThat(b.hash()).isNotNull();
  }

  @Test
  void anchor_mismatch_is_reported_when_the_tail_is_gone() {
    var sink = new InMemoryAuditSink();
    sink.append(event("a"));
    var last = sink.append(event("b"));
    var anchorOnly =
        new com.housedevinci.agentguard.domain.AuditAnchor() {
          @Override
          public java.util.Optional<Anchor> anchor() {
            return java.util.Optional.of(new Anchor(last.hash(), 3)); // anchor says three rows
          }
        };
    var report = new AuditChainVerifier(sink, anchorOnly).verify();
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.ANCHOR_MISMATCH);
    assertThat(report.intact()).isFalse();
  }

  @Test
  void keyed_chain_verifies_only_with_the_key() {
    var chain =
        com.housedevinci.agentguard.domain.AuditChain.keyed(
            "0123456789abcdef0123456789abcdef".getBytes());
    var sink = new InMemoryAuditSink(chain);
    sink.append(event("a"));
    sink.append(event("b"));
    assertThat(AuditChainVerifier.of(sink, chain).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT);
    assertThat(
            AuditChainVerifier.of(sink, com.housedevinci.agentguard.domain.AuditChain.unkeyed())
                .verify()
                .status())
        .isEqualTo(AuditChainVerifier.Status.BROKEN);
    var other =
        com.housedevinci.agentguard.domain.AuditChain.keyed(
            "fedcba9876543210fedcba9876543210".getBytes());
    assertThat(AuditChainVerifier.of(sink, other).verify().status())
        .isEqualTo(AuditChainVerifier.Status.BROKEN);
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> com.housedevinci.agentguard.domain.AuditChain.keyed("short".getBytes()))
        .isInstanceOf(IllegalArgumentException.class);
  }
}

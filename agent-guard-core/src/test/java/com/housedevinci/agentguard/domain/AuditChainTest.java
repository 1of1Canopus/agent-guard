package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class AuditChainTest {

  @Test
  void hash_covers_every_field_and_previous_hash() {
    var base =
        AuditEvent.builder()
            .timestamp(Instant.parse("2026-09-06T10:00:00Z"))
            .principalId("u1")
            .tenantId("acme")
            .tool("read")
            .argsHash("a")
            .resultHash("r")
            .latencyMillis(12)
            .decision(AuditDecision.ALLOWED)
            .correlationId("c1")
            .build();
    var h1 = AuditChain.hashOf(base, AuditChain.GENESIS);
    assertThat(h1).hasSize(64);
    assertThat(AuditChain.hashOf(base, "other")).isNotEqualTo(h1);
    assertThat(AuditChain.hashOf(base.withDecision(AuditDecision.DENIED), AuditChain.GENESIS))
        .isNotEqualTo(h1);
    assertThat(AuditChain.hashOf(base.withLatencyMillis(13), AuditChain.GENESIS)).isNotEqualTo(h1);
    assertThat(AuditChain.hashOf(base, AuditChain.GENESIS)).isEqualTo(h1);
  }

  @Test
  void chained_event_verifies_against_its_predecessor() {
    var e1 = AuditChain.link(sample("t1"), AuditChain.GENESIS);
    var e2 = AuditChain.link(sample("t2"), e1.hash());
    assertThat(e2.prevHash()).isEqualTo(e1.hash());
    assertThat(AuditChain.verify(e2, e1.hash())).isTrue();
    assertThat(AuditChain.verify(e2.withTool("tampered"), e1.hash())).isFalse();
  }

  private static AuditEvent sample(String tool) {
    return AuditEvent.builder()
        .timestamp(Instant.EPOCH)
        .principalId("p")
        .tool(tool)
        .argsHash("x")
        .decision(AuditDecision.ALLOWED)
        .correlationId("c")
        .build();
  }
}

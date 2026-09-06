package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Cipher probe (M2), flipped: the canonical form is length-prefixed, so moving a boundary between
 * two fields changes the hash.
 */
class CipherProbeAuditChainTest {

  private static AuditEvent event(
      String principal, String tenant, String correlation, String decisionId) {
    return AuditEvent.builder()
        .timestamp(Instant.parse("2026-09-06T10:00:00Z"))
        .principalId(principal)
        .tenantId(tenant)
        .tool("refund")
        .argsHash("a".repeat(64))
        .resultHash("")
        .latencyMillis(0)
        .decision(AuditDecision.ALLOWED)
        .correlationId(correlation)
        .decisionId(decisionId)
        .build();
  }

  @Test
  void canonical_form_is_unambiguous_across_field_boundaries() {
    var a = event("alice|x", "acme", "corr", null);
    var b = event("alice", "x|acme", "corr", null);
    assertThat(AuditChain.canonical(a)).isNotEqualTo(AuditChain.canonical(b));
    assertThat(AuditChain.hashOf(a, AuditChain.GENESIS))
        .isNotEqualTo(AuditChain.hashOf(b, AuditChain.GENESIS));

    var c = event("alice", "acme", "corr|" + "d".repeat(36), "e".repeat(36));
    var d = event("alice", "acme", "corr", "d".repeat(36) + "|" + "e".repeat(36));
    assertThat(AuditChain.canonical(c)).isNotEqualTo(AuditChain.canonical(d));
    var linkedA = AuditChain.link(a, AuditChain.GENESIS);
    assertThat(
            AuditChain.verify(b.withChain(linkedA.prevHash(), linkedA.hash()), AuditChain.GENESIS))
        .isFalse();

    // null and empty are different values, the actor is part of the material, timestamps are millis
    assertThat(AuditChain.canonical(event("p", null, "c", null)))
        .isNotEqualTo(AuditChain.canonical(event("p", "", "c", null)));
    var withActor =
        AuditEvent.builder()
            .timestamp(Instant.EPOCH)
            .principalId("p")
            .tool("t")
            .decision(AuditDecision.APPROVED)
            .actorId("alice")
            .build();
    assertThat(AuditChain.canonical(withActor)).contains("5:alice");
    assertThat(event("p", null, "c", null).timestamp().getNano() % 1_000_000).isZero();
  }
}

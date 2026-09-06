package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/** the security review security probes for the audit hash chain canonical form. */
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
  void probe_canonical_form_is_ambiguous_across_field_boundaries() {
    // the boundary between principal and tenant moves, the field count stays the same
    var a = event("alice|x", "acme", "corr", null);
    var b = event("alice", "x|acme", "corr", null);
    assertThat(a).isNotEqualTo(b);
    assertThat(AuditChain.canonical(a)).isEqualTo(AuditChain.canonical(b));
    assertThat(AuditChain.hashOf(a, AuditChain.GENESIS))
        .isEqualTo(AuditChain.hashOf(b, AuditChain.GENESIS));

    // same between correlation id and decision id (the link to the approval record)
    var c = event("alice", "acme", "corr|" + "d".repeat(36), "e".repeat(36));
    var d = event("alice", "acme", "corr", "d".repeat(36) + "|" + "e".repeat(36));
    assertThat(AuditChain.canonical(c)).isEqualTo(AuditChain.canonical(d));
    // a row rewritten from (c) to (d) or (a) to (b) keeps the chain intact
    var linkedA = AuditChain.link(a, AuditChain.GENESIS);
    assertThat(
            AuditChain.verify(b.withChain(linkedA.prevHash(), linkedA.hash()), AuditChain.GENESIS))
        .isTrue();
  }
}

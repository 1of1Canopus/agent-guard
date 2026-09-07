package com.housedevinci.agentguard.adapter.memory;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * the security review verification pass on 722e9a5: {@link InMemoryAuditSink} parity with {@code JdbcAuditSink}
 * on the keyed-from-birth refusals.
 */
class CipherProbeMemoryParityTest {

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

  private static byte[] key(int b) {
    var k = new byte[32];
    Arrays.fill(k, (byte) b);
    return k;
  }

  /** An unkeyed memory trail is INTACT_UNKEYED, never plain INTACT. */
  @Test
  void confirms_an_unkeyed_memory_trail_is_intact_unkeyed() {
    var sink = new InMemoryAuditSink();
    sink.append(event(1));
    assertThat(new AuditChainVerifier(sink, sink, Map.<String, byte[]>of()).verify().status())
        .isEqualTo(AuditChainVerifier.Status.INTACT_UNKEYED);
  }

  /** A keyed memory trail carries the key id on every row and verifies with the keyring. */
  @Test
  void confirms_a_keyed_memory_trail_carries_the_key_id() {
    var sink = new InMemoryAuditSink(AuditChain.keyed(key(3), "k9"));
    sink.append(event(1));
    var report = new AuditChainVerifier(sink, sink, Map.of("k9", key(3))).verify();
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.INTACT);
    assertThat(report.keyIds()).containsExactly("k9");
    assertThat(report.keyed()).isTrue();
  }

  /**
   * H7. The memory store's "anchor" is derived from the very list it anchors ({@code keyed} from
   * the live chain, {@code headHash}/{@code rowCount} from the last element), so it is not an
   * external record at all: deleting the tail of a memory trail is reported INTACT, where the JDBC
   * sink's separate anchor row reports ANCHOR_MISMATCH. Development-only store, but the class
   * javadoc says only that it has "nothing analogous to JdbcAuditSink's key-mismatch check" — it
   * also has no tail-deletion detection, and neither the javadoc nor SECURITY-NOTES says so.
   */
  @Test
  void probe_a_memory_trail_has_no_external_anchor() {
    var full = new InMemoryAuditSink(AuditChain.keyed(key(3), "k9"));
    full.append(event(1));
    full.append(event(2));
    full.append(event(3));
    // the same trail with its tail gone: the derived anchor follows the rows, so nothing mismatches
    var trimmed = new InMemoryAuditSink(AuditChain.keyed(key(3), "k9"));
    trimmed.append(event(1));

    var report = new AuditChainVerifier(trimmed, trimmed, Map.of("k9", key(3))).verify();
    assertThat(report.status()).isEqualTo(AuditChainVerifier.Status.INTACT);
    assertThat(report.anchored()).isTrue(); // reads as anchored, but the anchor is self-derived
    assertThat(report.verified()).isEqualTo(1);
  }
}

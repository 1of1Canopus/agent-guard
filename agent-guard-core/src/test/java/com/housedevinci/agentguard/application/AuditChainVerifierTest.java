package com.housedevinci.agentguard.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class AuditChainVerifierTest {

  private static AuditEvent event(String tool) {
    return AuditEvent.builder().timestamp(Instant.EPOCH).principalId("p").tool(tool)
        .decision(AuditDecision.ALLOWED).build();
  }

  @Test
  void empty_trail_is_intact() {
    assertThat(new AuditChainVerifier(new InMemoryAuditSink()).verify()).isEqualTo(new AuditChainVerifier.Report(0, -1));
  }

  @Test
  void detects_a_modified_row_in_the_middle() {
    var sink = new InMemoryAuditSink();
    for (int i = 0; i < 1200; i++) {
      sink.append(event("t" + i));
    }
    assertThat(new AuditChainVerifier(sink).verify().intact()).isTrue();
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
}

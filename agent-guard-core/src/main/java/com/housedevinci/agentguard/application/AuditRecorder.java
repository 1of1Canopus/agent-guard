package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.Hashes;
import com.housedevinci.agentguard.domain.Principal;
import java.time.Clock;
import java.util.Objects;

/**
 * Builds and appends audit events. A failing sink propagates: the module fails closed rather than
 * running tools unrecorded.
 */
public final class AuditRecorder {

  private final AuditSink sink;
  private final Clock clock;

  public AuditRecorder(AuditSink sink, Clock clock) {
    this.sink = Objects.requireNonNull(sink, "sink");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  public AuditEvent record(
      Principal principal,
      String tool,
      String argumentsJson,
      String result,
      long latencyMillis,
      AuditDecision decision,
      String correlationId,
      String decisionId) {
    var event =
        AuditEvent.builder()
            .timestamp(clock.instant())
            .principalId(principal.id())
            .tenantId(principal.tenantId().orElse(null))
            .tool(tool)
            .argsHash(Hashes.sha256Hex(argumentsJson))
            .resultHash(result == null ? "" : Hashes.sha256Hex(result))
            .latencyMillis(latencyMillis)
            .decision(decision)
            .correlationId(correlationId)
            .decisionId(decisionId)
            .build();
    return sink.append(event);
  }
}

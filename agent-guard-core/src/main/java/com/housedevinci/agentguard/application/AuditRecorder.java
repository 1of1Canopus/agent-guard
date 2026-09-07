package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.ArgumentCanonicalizer;
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
    return record(
        principal,
        tool,
        argumentsJson,
        result,
        latencyMillis,
        decision,
        correlationId,
        decisionId,
        null);
  }

  /** Same, with the human (or system) actor that caused the row, e.g. the approver. */
  public AuditEvent record(
      Principal principal,
      String tool,
      String argumentsJson,
      String result,
      long latencyMillis,
      AuditDecision decision,
      String correlationId,
      String decisionId,
      String actorId) {
    var event =
        AuditEvent.builder()
            .timestamp(clock.instant())
            .principalId(principal.id())
            .tenantId(principal.tenantId().orElse(null))
            .tool(tool)
            .argsHash(ArgumentCanonicalizer.hash(argumentsJson))
            .resultHash(result == null ? "" : Hashes.sha256Hex(result))
            .latencyMillis(latencyMillis)
            .decision(decision)
            .correlationId(correlationId)
            .decisionId(decisionId)
            .actorId(actorId)
            .build();
    return sink.append(event);
  }

  /**
   * Records a denial for arguments the guard refused to canonicalise (over {@code
   * maxArgumentBytes}): hashes the raw text directly instead of routing it through {@link
   * ArgumentCanonicalizer}, which parses the whole payload into a tree. A call rejected at this
   * boundary never reaches a decision row, so there is no canonical hash for this event to join
   * against (C4: the size cap must bound every parse of untrusted text, including the audit trail
   * of its own rejection).
   */
  public AuditEvent recordOversized(
      Principal principal, String tool, String argumentsJson, String correlationId) {
    var event =
        AuditEvent.builder()
            .timestamp(clock.instant())
            .principalId(principal.id())
            .tenantId(principal.tenantId().orElse(null))
            .tool(tool)
            .argsHash(Hashes.sha256Hex(argumentsJson))
            .resultHash("")
            .latencyMillis(0)
            .decision(AuditDecision.DENIED)
            .correlationId(correlationId)
            .decisionId(null)
            .actorId(null)
            .build();
    return sink.append(event);
  }
}

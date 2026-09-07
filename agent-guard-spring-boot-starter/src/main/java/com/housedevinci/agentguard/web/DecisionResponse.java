package com.housedevinci.agentguard.web;

import com.housedevinci.agentguard.domain.PendingDecision;
import java.time.Instant;

/** What the approval endpoints expose: the preview, never the raw arguments. */
public record DecisionResponse(
    String id,
    String principal,
    String tenant,
    String tool,
    String sideEffect,
    String argsPreview,
    String argsHash,
    Instant createdAt,
    Instant expiresAt,
    String state,
    String decidedBy,
    Instant decidedAt,
    boolean executed,
    String result) {

  public static DecisionResponse from(PendingDecision d) {
    return new DecisionResponse(
        d.id().toString(),
        d.principal().id(),
        d.principal().tenantId().orElse(null),
        d.tool().name(),
        d.tool().sideEffect().name(),
        d.argsPreview(),
        d.argsHash(),
        d.createdAt(),
        d.expiresAt(),
        d.state().name(),
        d.decidedBy(),
        d.decidedAt(),
        d.executed(),
        d.resultJson());
  }
}

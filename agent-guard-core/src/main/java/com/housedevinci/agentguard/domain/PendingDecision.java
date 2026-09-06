package com.housedevinci.agentguard.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * A tool call parked for a human decision.
 *
 * <p>{@code argumentsJson} is the exact input the tool will receive on resume; {@code argsHash}
 * binds the decision to it, and {@code argsPreview} is what humans and logs see (redacted, capped).
 *
 * @param id single-use decision id
 * @param principal who asked
 * @param tool which tool
 * @param argumentsJson the raw arguments (kept for execution; never shown)
 * @param argsHash SHA-256 of {@code argumentsJson}
 * @param argsPreview redacted, length-capped preview of the arguments
 * @param conversationId conversation the call belongs to, may be null
 * @param correlationId correlation id of the original call
 * @param createdAt when it was parked
 * @param expiresAt when it turns {@code EXPIRED} if nobody decides
 * @param state current state
 * @param decidedBy who approved / rejected, null while pending
 * @param decidedAt when, null while pending
 * @param executed whether the approved call has already run (single execution)
 * @param resultJson the tool result after execution, null before
 */
public record PendingDecision(
    DecisionId id,
    Principal principal,
    ToolRef tool,
    String argumentsJson,
    String argsHash,
    String argsPreview,
    String conversationId,
    String correlationId,
    Instant createdAt,
    Instant expiresAt,
    DecisionState state,
    String decidedBy,
    Instant decidedAt,
    boolean executed,
    String resultJson) {

  public PendingDecision {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(principal, "principal");
    Objects.requireNonNull(tool, "tool");
    argumentsJson = Objects.requireNonNullElse(argumentsJson, "");
    Objects.requireNonNull(argsHash, "argsHash");
    argsPreview = Objects.requireNonNullElse(argsPreview, "");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(state, "state");
    if (!expiresAt.isAfter(createdAt)) {
      throw new IllegalArgumentException("expiresAt must be after createdAt");
    }
  }

  /** Creates a fresh PENDING decision. */
  public static PendingDecision park(
      Principal principal,
      ToolRef tool,
      String argumentsJson,
      String argsPreview,
      String conversationId,
      String correlationId,
      Instant now,
      Instant expiresAt) {
    return new PendingDecision(
        DecisionId.random(),
        principal,
        tool,
        argumentsJson,
        Hashes.sha256Hex(argumentsJson),
        argsPreview,
        conversationId,
        correlationId,
        now,
        expiresAt,
        DecisionState.PENDING,
        null,
        null,
        false,
        null);
  }

  public boolean isExpiredAt(Instant now) {
    return state == DecisionState.PENDING && !now.isBefore(expiresAt);
  }

  /** Applies the state machine; throws on an illegal transition. */
  public PendingDecision decide(DecisionState target, String by, Instant at) {
    var next = state.transitionTo(target);
    return new PendingDecision(
        id, principal, tool, argumentsJson, argsHash, argsPreview, conversationId, correlationId,
        createdAt, expiresAt, next, by, at, executed, resultJson);
  }

  public PendingDecision withExecuted(String result) {
    return new PendingDecision(
        id, principal, tool, argumentsJson, argsHash, argsPreview, conversationId, correlationId,
        createdAt, expiresAt, state, decidedBy, decidedAt, true, result);
  }

  public Optional<String> result() {
    return Optional.ofNullable(resultJson);
  }

  /** True when the stored arguments still hash to the approved hash. */
  public boolean argumentsIntact() {
    return Hashes.sha256Hex(argumentsJson).equals(argsHash);
  }
}

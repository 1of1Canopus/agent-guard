package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.ApprovalHashMismatchException;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionNotFoundException;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.IllegalDecisionTransitionException;
import com.housedevinci.agentguard.domain.Notifier;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.ToolRef;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Parks calls and records human decisions. Approving also resumes (executes once) through the
 * {@link DecisionResumer}; a second approval of the same decision is a no-op that returns the
 * stored result. Rejecting or approving a decision that already reached another terminal state
 * throws {@link IllegalDecisionTransitionException}.
 */
public final class ApprovalService {

  private final DecisionStore store;
  private final Notifier notifier;
  private final DecisionResumer resumer;
  private final AuditRecorder audit;
  private final Clock clock;
  private final Duration ttl;

  public ApprovalService(
      DecisionStore store,
      Notifier notifier,
      DecisionResumer resumer,
      AuditRecorder audit,
      Clock clock,
      Duration ttl) {
    this.store = Objects.requireNonNull(store, "store");
    this.notifier = Objects.requireNonNull(notifier, "notifier");
    this.resumer = Objects.requireNonNull(resumer, "resumer");
    this.audit = Objects.requireNonNull(audit, "audit");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.ttl = Objects.requireNonNull(ttl, "ttl");
    if (ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("approval ttl must be positive");
    }
  }

  /** Result of a human decision: the decision itself and, for approvals, the tool result. */
  public record Outcome(PendingDecision decision, GuardResult result) {}

  public PendingDecision park(ToolInvocation invocation, ToolRef tool, String argsPreview) {
    var now = clock.instant();
    var decision =
        PendingDecision.park(
            invocation.principal(),
            tool,
            invocation.argumentsJson(),
            argsPreview,
            invocation.conversationId(),
            invocation.correlationId(),
            now,
            now.plus(ttl));
    store.save(decision);
    notifier.notify(decision);
    return decision;
  }

  /**
   * Approves after the approver attested the arguments hash they reviewed (the endpoints always
   * require it).
   *
   * @throws ApprovalHashMismatchException when {@code attestedArgsHash} differs from the decision's
   */
  public Outcome approve(DecisionId id, String approver, String attestedArgsHash) {
    var decision = load(id);
    if (attestedArgsHash == null || !attestedArgsHash.equalsIgnoreCase(decision.argsHash())) {
      throw new ApprovalHashMismatchException(id);
    }
    return approve(id, approver);
  }

  /** Programmatic approval without hash attestation (the caller has the decision in hand). */
  public Outcome approve(DecisionId id, String approver) {
    var decision = load(id);
    if (decision.state() == DecisionState.APPROVED) {
      var result = resumer.resume(id); // idempotent: returns the stored result, runs nothing
      return new Outcome(load(id), result);
    }
    if (!store.transition(
        id, DecisionState.PENDING, DecisionState.APPROVED, approver, clock.instant())) {
      throw new IllegalDecisionTransitionException(load(id).state(), DecisionState.APPROVED);
    }
    var result =
        resumer.resume(id); // executes once, then the reloaded decision shows executed=true
    return new Outcome(load(id), result);
  }

  public PendingDecision reject(DecisionId id, String approver) {
    var decision = load(id);
    if (decision.state() == DecisionState.REJECTED) {
      return decision;
    }
    if (!store.transition(
        id, DecisionState.PENDING, DecisionState.REJECTED, approver, clock.instant())) {
      throw new IllegalDecisionTransitionException(load(id).state(), DecisionState.REJECTED);
    }
    var rejected = load(id);
    audit.record(
        rejected.principal(),
        rejected.tool().name(),
        rejected.argumentsJson(),
        null,
        0,
        AuditDecision.REJECTED,
        rejected.correlationId(),
        id.toString(),
        approver);
    return rejected;
  }

  public Optional<PendingDecision> find(DecisionId id) {
    return store.findById(id).map(this::expireIfOverdue);
  }

  public List<PendingDecision> pending(int limit) {
    return store.findByState(DecisionState.PENDING, limit).stream()
        .map(this::expireIfOverdue)
        .filter(d -> d.state() == DecisionState.PENDING)
        .toList();
  }

  /** Marks overdue PENDING decisions EXPIRED; returns how many. */
  public int expireOverdue() {
    int n = 0;
    for (var d : store.findByState(DecisionState.PENDING, 1000)) {
      if (expireIfOverdue(d).state() == DecisionState.EXPIRED) {
        n++;
      }
    }
    return n;
  }

  PendingDecision load(DecisionId id) {
    return store
        .findById(id)
        .map(this::expireIfOverdue)
        .orElseThrow(() -> new DecisionNotFoundException(id));
  }

  private PendingDecision expireIfOverdue(PendingDecision d) {
    var now = clock.instant();
    if (d.isExpiredAt(now)
        && store.transition(d.id(), DecisionState.PENDING, DecisionState.EXPIRED, "system", now)) {
      audit.record(
          d.principal(),
          d.tool().name(),
          d.argumentsJson(),
          null,
          0,
          AuditDecision.EXPIRED,
          d.correlationId(),
          d.id().toString());
      return store.findById(d.id()).orElse(d);
    }
    return store.findById(d.id()).orElse(d);
  }
}

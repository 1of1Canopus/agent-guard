package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.ArgumentsTamperedException;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionNotFoundException;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.PendingDecision;
import java.time.Clock;
import java.util.Objects;

/**
 * Executes an approved decision exactly once and stores the result. Idempotent by decision id:
 * later resumes return the stored result. Verifies the argument hash before running, runs the
 * closure captured when the decision was parked, inside the parking principal's context ({@link
 * ResumeContextProvider}). The budget was reserved at park time and is not charged again.
 */
public final class DecisionResumer {

  private final DecisionStore store;
  private final ToolExecutorRegistry executors;
  private final AuditRecorder audit;
  private final ResumeContextProvider context;
  private final Clock clock;

  public DecisionResumer(
      DecisionStore store,
      ToolExecutorRegistry executors,
      AuditRecorder audit,
      ResumeContextProvider context,
      Clock clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.executors = Objects.requireNonNull(executors, "executors");
    this.audit = Objects.requireNonNull(audit, "audit");
    this.context = Objects.requireNonNull(context, "context");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  public GuardResult resume(DecisionId id) {
    var decision = store.findById(id).orElseThrow(() -> new DecisionNotFoundException(id));
    return switch (decision.state()) {
      case PENDING -> new GuardResult.AwaitingApproval(decision);
      case REJECTED ->
          new GuardResult.Denied(
              ErrorCodes.APPROVAL_REJECTED,
              decision.tool().name(),
              "rejected by " + decision.decidedBy());
      case EXPIRED ->
          new GuardResult.Denied(
              ErrorCodes.APPROVAL_EXPIRED, decision.tool().name(), "approval expired");
      case APPROVED -> executeOnce(decision);
    };
  }

  private GuardResult executeOnce(PendingDecision decision) {
    if (!decision.argumentsIntact()) {
      throw new ArgumentsTamperedException(decision.id());
    }
    if (!store.markExecutedOnce(decision.id())) {
      var stored = store.findById(decision.id()).orElse(decision);
      return stored
          .result()
          .<GuardResult>map(GuardResult.Executed::new)
          .orElseGet(
              () ->
                  new GuardResult.Failed(
                      decision.tool().name(), "already executed, result not yet stored"));
    }
    var tool = decision.tool().name();
    var actor = decision.decidedBy();
    var executor = executors.find(decision.id());
    if (executor.isEmpty()) {
      var failed =
          new GuardResult.Denied(
              ErrorCodes.APPROVAL_NO_EXECUTOR,
              tool,
              "no executor captured for this decision (parked before a restart?)");
      store.storeResult(decision.id(), failed.toModelText());
      audit.record(
          decision.principal(),
          tool,
          decision.argumentsJson(),
          null,
          0,
          AuditDecision.FAILED,
          decision.correlationId(),
          decision.id().toString(),
          actor);
      return failed;
    }
    long start = clock.millis();
    try {
      String output =
          context.runAs(decision, () -> executor.get().execute(decision.argumentsJson()));
      long latency = clock.millis() - start;
      store.storeResult(decision.id(), output);
      audit.record(
          decision.principal(),
          tool,
          decision.argumentsJson(),
          output,
          latency,
          AuditDecision.APPROVED,
          decision.correlationId(),
          decision.id().toString(),
          actor);
      return new GuardResult.Executed(output);
    } catch (Exception e) {
      long latency = clock.millis() - start;
      var failed = new GuardResult.Failed(tool, Errors.describe(e));
      store.storeResult(decision.id(), failed.toModelText());
      audit.record(
          decision.principal(),
          tool,
          decision.argumentsJson(),
          null,
          latency,
          AuditDecision.FAILED,
          decision.correlationId(),
          decision.id().toString(),
          actor);
      return failed;
    } finally {
      executors.remove(decision.id());
    }
  }
}

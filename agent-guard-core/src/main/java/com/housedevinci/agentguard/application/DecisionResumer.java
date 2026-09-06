package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.ArgumentsTamperedException;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.BudgetExceededException;
import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionNotFoundException;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.PendingDecision;
import java.time.Clock;
import java.util.Objects;

/**
 * Executes an approved decision exactly once and stores the result. Idempotent by decision id:
 * later resumes return the stored result. Verifies the argument hash before running.
 */
public final class DecisionResumer {

  private final DecisionStore store;
  private final ToolExecutorRegistry executors;
  private final BudgetEnforcer budgets;
  private final AuditRecorder audit;
  private final Clock clock;

  public DecisionResumer(
      DecisionStore store,
      ToolExecutorRegistry executors,
      BudgetEnforcer budgets,
      AuditRecorder audit,
      Clock clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.executors = Objects.requireNonNull(executors, "executors");
    this.budgets = Objects.requireNonNull(budgets, "budgets");
    this.audit = Objects.requireNonNull(audit, "audit");
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
    var invocation =
        new ToolInvocation(
            decision.principal(),
            tool,
            decision.argumentsJson(),
            decision.conversationId(),
            decision.correlationId());
    var executor = executors.find(tool);
    if (executor.isEmpty()) {
      var failed =
          new GuardResult.Denied(
              ErrorCodes.APPROVAL_NO_EXECUTOR, tool, "no executor registered for tool");
      store.storeResult(decision.id(), failed.toModelText());
      audit.record(decision.principal(), tool, decision.argumentsJson(), null, 0,
          AuditDecision.FAILED, decision.correlationId(), decision.id().toString());
      return failed;
    }
    try {
      budgets.reserve(invocation);
    } catch (BudgetExceededException e) {
      var result = new GuardResult.BudgetExceeded(tool, e.getMessage());
      store.storeResult(decision.id(), result.toModelText());
      audit.record(decision.principal(), tool, decision.argumentsJson(), null, 0,
          AuditDecision.BUDGET_EXCEEDED, decision.correlationId(), decision.id().toString());
      return result;
    }
    long start = clock.millis();
    try {
      String output = executor.get().execute(decision.argumentsJson());
      long latency = clock.millis() - start;
      store.storeResult(decision.id(), output);
      audit.record(decision.principal(), tool, decision.argumentsJson(), output, latency,
          AuditDecision.APPROVED, decision.correlationId(), decision.id().toString());
      return new GuardResult.Executed(output);
    } catch (Exception e) {
      long latency = clock.millis() - start;
      var failed = new GuardResult.Failed(tool, Errors.describe(e));
      store.storeResult(decision.id(), failed.toModelText());
      audit.record(decision.principal(), tool, decision.argumentsJson(), null, latency,
          AuditDecision.FAILED, decision.correlationId(), decision.id().toString());
      return failed;
    }
  }
}

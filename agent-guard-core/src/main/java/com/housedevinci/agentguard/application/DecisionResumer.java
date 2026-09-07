package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.ArgumentsTamperedException;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionNotFoundException;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.PolicyDecision;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.ToolPolicyEvaluator;
import com.housedevinci.agentguard.domain.ToolRef;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;

/**
 * Executes an approved decision exactly once and stores the result. Idempotent by decision id:
 * later resumes return the stored result. Before running: the argument hash is verified (a mismatch
 * closes the decision, is audited as {@code TAMPERED} and thrown), the principal is refreshed
 * ({@link PrincipalRefresher}) and the policy re-evaluated (a revoked role or a tightened rule
 * denies), then the closure captured at park time runs inside the parking principal's context
 * ({@link ResumeContextProvider}). The budget was reserved at park time and is not charged again.
 */
public final class DecisionResumer {

  private final DecisionStore store;
  private final ToolExecutorRegistry executors;
  private final AuditRecorder audit;
  private final ResumeContextProvider context;
  private final PolicyLookup policies;
  private final ToolPolicyEvaluator evaluator;
  private final PrincipalRefresher refresher;
  private final boolean includeToolMessage;
  private final Clock clock;

  public DecisionResumer(
      DecisionStore store,
      ToolExecutorRegistry executors,
      AuditRecorder audit,
      ResumeContextProvider context,
      PolicyLookup policies,
      ToolPolicyEvaluator evaluator,
      PrincipalRefresher refresher,
      boolean includeToolMessage,
      Clock clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.executors = Objects.requireNonNull(executors, "executors");
    this.audit = Objects.requireNonNull(audit, "audit");
    this.context = Objects.requireNonNull(context, "context");
    this.policies = Objects.requireNonNull(policies, "policies");
    this.evaluator = Objects.requireNonNull(evaluator, "evaluator");
    this.refresher = Objects.requireNonNull(refresher, "refresher");
    this.includeToolMessage = includeToolMessage;
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
    var tool = decision.tool().name();
    var actor = decision.decidedBy();
    if (!decision.argumentsIntact()) {
      // close the decision so it can never run, leave a row, then refuse
      if (store.markExecutedOnce(decision.id())) {
        store.storeResult(
            decision.id(),
            new GuardResult.Denied(ErrorCodes.APPROVAL_ARGS_TAMPERED, tool, "arguments tampered")
                .toModelText());
        audit.record(
            decision.principal(),
            tool,
            decision.argumentsJson(),
            null,
            0,
            AuditDecision.TAMPERED,
            decision.correlationId(),
            decision.id().toString(),
            actor);
      }
      throw new ArgumentsTamperedException(decision.id());
    }
    if (!store.markExecutedOnce(decision.id())) {
      var stored = store.findById(decision.id()).orElse(decision);
      return stored
          .result()
          .<GuardResult>map(GuardResult.Executed::new)
          .orElseGet(
              () -> new GuardResult.Failed(tool, "already executed, result not yet stored", false));
    }
    try {
      Principal principal = refresher.refresh(decision.principal()).orElse(decision.principal());
      Optional<GuardResult> refused = recheckPolicy(decision, principal, actor);
      if (refused.isPresent()) {
        return refused.get();
      }
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
        var failed =
            new GuardResult.Failed(
                tool, Errors.describe(e, decision.correlationId(), includeToolMessage), false);
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
      }
    } finally {
      executors.remove(decision.id());
    }
  }

  private Optional<GuardResult> recheckPolicy(
      PendingDecision decision, Principal principal, String actor) {
    var tool = decision.tool().name();
    Optional<PolicyRule> rule = policies.resolve(tool, Optional.of(decision.tool().sideEffect()));
    GuardResult refused = null;
    if (rule.isEmpty()) {
      refused =
          new GuardResult.Denied(
              ErrorCodes.POLICY_UNREGISTERED, tool, "tool no longer has a policy");
    } else {
      PolicyDecision d =
          evaluator.evaluate(rule.get(), principal, new ToolRef(tool, rule.get().sideEffect()));
      if (d instanceof PolicyDecision.Deny deny) {
        refused =
            new GuardResult.Denied(
                deny.code(), tool, deny.reason() + " (re-evaluated at approval)");
      }
    }
    if (refused == null) {
      return Optional.empty();
    }
    store.storeResult(decision.id(), refused.toModelText());
    audit.record(
        principal,
        tool,
        decision.argumentsJson(),
        null,
        0,
        AuditDecision.DENIED,
        decision.correlationId(),
        decision.id().toString(),
        actor);
    return Optional.of(refused);
  }
}

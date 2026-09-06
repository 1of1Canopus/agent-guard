package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.ArgumentRedactor;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.BudgetExceededException;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.Hashes;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.PolicyDecision;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolPolicyEvaluator;
import com.housedevinci.agentguard.domain.ToolRef;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;

/**
 * The pipeline every intercepted tool call goes through: policy, approval gate, budget, execute,
 * audit. Framework adapters (Spring AI {@code ToolCallback}, MCP {@code SyncToolSpecification})
 * call {@link #execute} and render the {@link GuardResult}.
 */
public final class ToolGuard {

  private final PolicyLookup policies;
  private final ToolPolicyEvaluator evaluator;
  private final BudgetEnforcer budgets;
  private final ApprovalService approvals;
  private final DecisionResumer resumer;
  private final DecisionStore decisions;
  private final ToolExecutorRegistry executors;
  private final AuditRecorder audit;
  private final ArgumentRedactor redactor;
  private final Clock clock;

  public ToolGuard(
      PolicyLookup policies,
      ToolPolicyEvaluator evaluator,
      BudgetEnforcer budgets,
      ApprovalService approvals,
      DecisionResumer resumer,
      DecisionStore decisions,
      ToolExecutorRegistry executors,
      AuditRecorder audit,
      ArgumentRedactor redactor,
      Clock clock) {
    this.policies = Objects.requireNonNull(policies);
    this.evaluator = Objects.requireNonNull(evaluator);
    this.budgets = Objects.requireNonNull(budgets);
    this.approvals = Objects.requireNonNull(approvals);
    this.resumer = Objects.requireNonNull(resumer);
    this.decisions = Objects.requireNonNull(decisions);
    this.executors = Objects.requireNonNull(executors);
    this.audit = Objects.requireNonNull(audit);
    this.redactor = Objects.requireNonNull(redactor);
    this.clock = Objects.requireNonNull(clock);
  }

  /**
   * Guards one call.
   *
   * @param invocation the actual call
   * @param sideEffectHint side effect known from the integration (MCP hints), if any
   * @param executor the real tool
   */
  public GuardResult execute(
      ToolInvocation invocation, Optional<SideEffect> sideEffectHint, ToolExecutor executor) {
    var toolName = invocation.toolName();
    var principal = invocation.principal();
    Optional<PolicyRule> rule = policies.resolve(toolName, sideEffectHint);
    if (rule.isEmpty()) {
      audit.record(
          principal,
          toolName,
          invocation.argumentsJson(),
          null,
          0,
          AuditDecision.DENIED,
          invocation.correlationId(),
          null);
      return new GuardResult.Denied(
          ErrorCodes.POLICY_UNREGISTERED,
          toolName,
          "tool has no policy; set agentguard.policy.unregistered-tools or add @ToolPolicy");
    }
    var tool = new ToolRef(toolName, rule.get().sideEffect());
    PolicyDecision decision = evaluator.evaluate(rule.get(), principal, tool);
    return switch (decision) {
      case PolicyDecision.Deny deny -> {
        audit.record(
            principal,
            toolName,
            invocation.argumentsJson(),
            null,
            0,
            AuditDecision.DENIED,
            invocation.correlationId(),
            null);
        yield new GuardResult.Denied(deny.code(), toolName, deny.reason());
      }
      case PolicyDecision.RequireApproval ra -> gate(invocation, tool, executor);
      case PolicyDecision.Allow allow -> dispatch(invocation, executor);
    };
  }

  private GuardResult gate(ToolInvocation invocation, ToolRef tool, ToolExecutor executor) {
    executors.register(tool.name(), executor);
    var argsHash = Hashes.sha256Hex(invocation.argumentsJson());
    Optional<PendingDecision> existing =
        decisions
            .findLatest(invocation.principal().id(), tool.name(), argsHash)
            .flatMap(d -> approvals.find(d.id()));
    if (existing.isPresent()) {
      var d = existing.get();
      if (d.state() == DecisionState.PENDING) {
        audit.record(
            invocation.principal(),
            tool.name(),
            invocation.argumentsJson(),
            null,
            0,
            AuditDecision.PENDING,
            invocation.correlationId(),
            d.id().toString());
        return new GuardResult.AwaitingApproval(d);
      }
      if (d.state() == DecisionState.APPROVED || d.state() == DecisionState.REJECTED) {
        return resumer.resume(d.id());
      }
      // EXPIRED: fall through and park again
    }
    var parked = approvals.park(invocation, tool, redactor.preview(invocation.argumentsJson()));
    audit.record(
        invocation.principal(),
        tool.name(),
        invocation.argumentsJson(),
        null,
        0,
        AuditDecision.PENDING,
        invocation.correlationId(),
        parked.id().toString());
    return new GuardResult.AwaitingApproval(parked);
  }

  private GuardResult dispatch(ToolInvocation invocation, ToolExecutor executor) {
    var tool = invocation.toolName();
    try {
      budgets.reserve(invocation);
    } catch (BudgetExceededException e) {
      audit.record(
          invocation.principal(),
          tool,
          invocation.argumentsJson(),
          null,
          0,
          AuditDecision.BUDGET_EXCEEDED,
          invocation.correlationId(),
          null);
      return new GuardResult.BudgetExceeded(tool, e.getMessage());
    }
    long start = clock.millis();
    try {
      String output = executor.execute(invocation.argumentsJson());
      audit.record(
          invocation.principal(),
          tool,
          invocation.argumentsJson(),
          output,
          clock.millis() - start,
          AuditDecision.ALLOWED,
          invocation.correlationId(),
          null);
      return new GuardResult.Executed(output);
    } catch (Exception e) {
      audit.record(
          invocation.principal(),
          tool,
          invocation.argumentsJson(),
          null,
          clock.millis() - start,
          AuditDecision.FAILED,
          invocation.correlationId(),
          null);
      return new GuardResult.Failed(tool, Errors.describe(e));
    }
  }

  public ApprovalService approvals() {
    return approvals;
  }

  public BudgetEnforcer budgets() {
    return budgets;
  }

  public PolicyLookup policies() {
    return policies;
  }
}

package com.housedevinci.agentguard.domain;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * Pure policy evaluation: roles, scopes and tenants are checked in that order (first failure
 * wins); then the side effect decides between {@code ALLOW} and {@code REQUIRE_APPROVAL}.
 *
 * <p>Evaluated on the actual call, never on model intent.
 */
public final class ToolPolicyEvaluator {

  private final Set<SideEffect> approvalRequiredFor;

  public ToolPolicyEvaluator(Set<SideEffect> approvalRequiredFor) {
    Objects.requireNonNull(approvalRequiredFor, "approvalRequiredFor");
    this.approvalRequiredFor =
        approvalRequiredFor.isEmpty()
            ? EnumSet.noneOf(SideEffect.class)
            : EnumSet.copyOf(approvalRequiredFor);
  }

  /** WRITE and DESTRUCTIVE require approval. */
  public static ToolPolicyEvaluator defaults() {
    return new ToolPolicyEvaluator(EnumSet.of(SideEffect.WRITE, SideEffect.DESTRUCTIVE));
  }

  public PolicyDecision evaluate(PolicyRule rule, Principal principal, ToolRef tool) {
    Objects.requireNonNull(rule, "rule");
    Objects.requireNonNull(principal, "principal");
    Objects.requireNonNull(tool, "tool");
    if (!rule.roles().isEmpty() && !principal.hasAnyRole(rule.roles())) {
      return PolicyDecision.deny(
          ErrorCodes.POLICY_ROLE, "requires one of roles " + sorted(rule.roles()));
    }
    if (!rule.scopes().isEmpty() && !principal.hasAnyScope(rule.scopes())) {
      return PolicyDecision.deny(
          ErrorCodes.POLICY_SCOPE, "requires one of scopes " + sorted(rule.scopes()));
    }
    if (!rule.tenants().isEmpty()
        && principal.tenantId().filter(rule.tenants()::contains).isEmpty()) {
      return PolicyDecision.deny(ErrorCodes.POLICY_TENANT, "tool is not enabled for this tenant");
    }
    if (approvalRequiredFor.contains(rule.sideEffect())) {
      return PolicyDecision.requireApproval();
    }
    return PolicyDecision.allow();
  }

  public Set<SideEffect> approvalRequiredFor() {
    return Set.copyOf(approvalRequiredFor);
  }

  private static String sorted(Set<String> values) {
    return values.stream().sorted().toList().toString();
  }
}

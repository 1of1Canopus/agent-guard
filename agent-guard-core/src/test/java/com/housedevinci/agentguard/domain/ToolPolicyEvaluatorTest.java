package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ToolPolicyEvaluatorTest {

  private static final ToolPolicyEvaluator EVALUATOR = ToolPolicyEvaluator.defaults();

  private static Principal principal(Set<String> roles, Set<String> scopes, String tenant) {
    return new Principal("u1", roles, scopes, tenant);
  }

  static Stream<Arguments> matrix() {
    var anyRule = PolicyRule.unrestricted(SideEffect.READ);
    var adminRead = new PolicyRule(Set.of("ADMIN"), Set.of(), Set.of(), SideEffect.READ);
    var scopedRead = new PolicyRule(Set.of(), Set.of("tools:read"), Set.of(), SideEffect.READ);
    var tenantRead = new PolicyRule(Set.of(), Set.of(), Set.of("acme"), SideEffect.READ);
    var adminWrite = new PolicyRule(Set.of("ADMIN"), Set.of(), Set.of(), SideEffect.WRITE);
    var destructive = PolicyRule.unrestricted(SideEffect.DESTRUCTIVE);
    var full =
        new PolicyRule(
            Set.of("ADMIN", "OPS"), Set.of("tools:write"), Set.of("acme"), SideEffect.WRITE);
    return Stream.of(
        Arguments.of("no restriction, READ", anyRule, principal(Set.of(), Set.of(), null), "ALLOW"),
        Arguments.of("role match", adminRead, principal(Set.of("ADMIN"), Set.of(), null), "ALLOW"),
        Arguments.of("role miss", adminRead, principal(Set.of("VIEWER"), Set.of(), null), "DENY"),
        Arguments.of("role missing entirely", adminRead, principal(Set.of(), Set.of(), null), "DENY"),
        Arguments.of("scope match", scopedRead, principal(Set.of(), Set.of("tools:read"), null), "ALLOW"),
        Arguments.of("scope miss", scopedRead, principal(Set.of(), Set.of("tools:write"), null), "DENY"),
        Arguments.of("tenant match", tenantRead, principal(Set.of(), Set.of(), "acme"), "ALLOW"),
        Arguments.of("tenant miss", tenantRead, principal(Set.of(), Set.of(), "other"), "DENY"),
        Arguments.of("tenant required, principal has none", tenantRead, principal(Set.of(), Set.of(), null), "DENY"),
        Arguments.of("WRITE with role", adminWrite, principal(Set.of("ADMIN"), Set.of(), null), "REQUIRE_APPROVAL"),
        Arguments.of("WRITE without role denied before approval", adminWrite, principal(Set.of("VIEWER"), Set.of(), null), "DENY"),
        Arguments.of("DESTRUCTIVE unrestricted", destructive, principal(Set.of(), Set.of(), null), "REQUIRE_APPROVAL"),
        Arguments.of("all constraints satisfied", full, principal(Set.of("OPS"), Set.of("tools:write"), "acme"), "REQUIRE_APPROVAL"),
        Arguments.of("all but scope", full, principal(Set.of("OPS"), Set.of("nope"), "acme"), "DENY"),
        Arguments.of("all but tenant", full, principal(Set.of("OPS"), Set.of("tools:write"), "zeta"), "DENY"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("matrix")
  void policy_matrix(String label, PolicyRule rule, Principal principal, String expected) {
    PolicyDecision decision = EVALUATOR.evaluate(rule, principal, new ToolRef("t", rule.sideEffect()));
    assertThat(decision.kind().name()).isEqualTo(expected);
  }

  @Test
  void deny_carries_stable_code_and_reason() {
    var rule = new PolicyRule(Set.of("ADMIN"), Set.of(), Set.of(), SideEffect.READ);
    var decision =
        EVALUATOR.evaluate(rule, principal(Set.of(), Set.of(), null), new ToolRef("t", SideEffect.READ));
    assertThat(decision).isInstanceOf(PolicyDecision.Deny.class);
    var deny = (PolicyDecision.Deny) decision;
    assertThat(deny.code()).isEqualTo("AG-POLICY-001");
    assertThat(deny.reason()).contains("role");
  }

  @Test
  void approval_set_is_configurable() {
    var evaluator = new ToolPolicyEvaluator(EnumSet.of(SideEffect.DESTRUCTIVE));
    var write =
        evaluator.evaluate(
            PolicyRule.unrestricted(SideEffect.WRITE),
            principal(Set.of(), Set.of(), null),
            new ToolRef("t", SideEffect.WRITE));
    var destructive =
        evaluator.evaluate(
            PolicyRule.unrestricted(SideEffect.DESTRUCTIVE),
            principal(Set.of(), Set.of(), null),
            new ToolRef("t", SideEffect.DESTRUCTIVE));
    assertThat(write.kind()).isEqualTo(PolicyDecision.Kind.ALLOW);
    assertThat(destructive.kind()).isEqualTo(PolicyDecision.Kind.REQUIRE_APPROVAL);
  }

  @Test
  void principal_rejects_null_id_and_normalises_blank_tenant() {
    var p = new Principal("x", Set.of(), Set.of(), " ");
    assertThat(p.tenantId()).isEmpty();
    assertThatThrownBy(() -> new Principal(null, Set.of(), Set.of(), null))
        .isInstanceOf(NullPointerException.class);
  }
}

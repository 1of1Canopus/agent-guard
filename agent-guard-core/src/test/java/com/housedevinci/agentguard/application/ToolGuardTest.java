package com.housedevinci.agentguard.application;

import static com.housedevinci.agentguard.application.GuardFixture.AGENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.domain.ArgumentsTamperedException;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.IllegalDecisionTransitionException;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ToolGuardTest {

  private final GuardFixture f = new GuardFixture();
  private final AtomicInteger writes = new AtomicInteger();

  @BeforeEach
  void policies() {
    f.registry.register("read", PolicyRule.unrestricted(SideEffect.READ));
    f.registry.register(
        "write", new PolicyRule(Set.of("AGENT"), Set.of(), Set.of(), SideEffect.WRITE));
    f.registry.register(
        "admin_only", new PolicyRule(Set.of("ADMIN"), Set.of(), Set.of(), SideEffect.READ));
  }

  private GuardResult call(String tool, String args) {
    return f.guard.execute(
        ToolInvocation.of(AGENT, tool, args),
        Optional.empty(),
        a -> {
          if (tool.equals("write")) {
            writes.incrementAndGet();
          }
          return "{\"ok\":true,\"echo\":" + a + "}";
        });
  }

  @Test
  void read_tool_is_executed_and_audited_as_allowed() {
    var result = call("read", "{\"q\":1}");
    assertThat(result).isInstanceOf(GuardResult.Executed.class);
    assertThat(result.toModelText()).contains("\"ok\":true");
    assertThat(f.auditSink.latest(1).get(0).decision()).isEqualTo(AuditDecision.ALLOWED);
  }

  @Test
  void role_miss_is_denied_with_structured_error() {
    var result = call("admin_only", "{}");
    assertThat(result).isInstanceOf(GuardResult.Denied.class);
    assertThat(result.toModelText())
        .contains("\"error\":\"TOOL_DENIED\"")
        .contains("AG-POLICY-001");
    assertThat(result.toModelText()).doesNotContain("Exception").doesNotContain("\tat ");
    assertThat(f.auditSink.latest(1).get(0).decision()).isEqualTo(AuditDecision.DENIED);
  }

  @Test
  void unregistered_tool_is_denied_by_default() {
    var result = call("mystery", "{}");
    assertThat(result.toModelText())
        .contains("AG-POLICY-004")
        .contains("agentguard.policy.unregistered-tools");
  }

  @Test
  void unregistered_tool_can_be_allowed_by_behaviour() {
    var fx = new GuardFixture(UnregisteredToolBehaviour.ALLOW, java.util.List.of());
    var r = fx.guard.execute(ToolInvocation.of(AGENT, "mystery", "{}"), Optional.empty(), a -> "x");
    assertThat(r).isInstanceOf(GuardResult.Executed.class);
  }

  @Test
  void mcp_hint_is_used_when_no_policy_is_registered() {
    var r =
        f.guard.execute(
            ToolInvocation.of(AGENT, "hinted", "{}"),
            Optional.of(SideEffect.DESTRUCTIVE),
            a -> "x");
    assertThat(r).isInstanceOf(GuardResult.AwaitingApproval.class);
  }

  @Test
  void write_tool_is_parked_notified_and_not_executed() {
    var result = call("write", "{\"amount\":5,\"password\":\"x\"}");
    assertThat(result).isInstanceOf(GuardResult.AwaitingApproval.class);
    assertThat(result.toModelText()).contains("AWAITING_APPROVAL").contains("decisionId");
    assertThat(writes).hasValue(0);
    assertThat(f.notified).hasSize(1);
    PendingDecision d = f.notified.get(0);
    assertThat(d.state()).isEqualTo(DecisionState.PENDING);
    assertThat(d.argsPreview()).contains("\"password\":\"***\"").contains("\"amount\":5");
    assertThat(f.auditSink.latest(1).get(0).decision()).isEqualTo(AuditDecision.PENDING);
  }

  @Test
  void repeated_call_while_pending_does_not_park_twice() {
    call("write", "{\"a\":1}");
    var again = call("write", "{\"a\":1}");
    assertThat(again).isInstanceOf(GuardResult.AwaitingApproval.class);
    assertThat(f.notified).hasSize(1);
    assertThat(f.decisions.findByState(DecisionState.PENDING, 10)).hasSize(1);
  }

  @Test
  void approve_executes_exactly_once_and_second_approve_is_a_noop() {
    var parked = (GuardResult.AwaitingApproval) call("write", "{\"a\":1}");
    var id = parked.decision().id();

    var first = f.approvals.approve(id, "alice");
    assertThat(first.result()).isInstanceOf(GuardResult.Executed.class);
    assertThat(first.decision().state()).isEqualTo(DecisionState.APPROVED);
    assertThat(first.decision().decidedBy()).isEqualTo("alice");
    assertThat(writes).hasValue(1);

    var second = f.approvals.approve(id, "bob");
    assertThat(second.result().toModelText()).isEqualTo(first.result().toModelText());
    assertThat(second.decision().decidedBy()).isEqualTo("alice");
    assertThat(writes).hasValue(1);

    // the agent re-calling with the same args gets the stored result, no re-execution
    var replay = call("write", "{\"a\":1}");
    assertThat(replay).isInstanceOf(GuardResult.Executed.class);
    assertThat(writes).hasValue(1);

    var decisions = f.auditSink.latest(10).stream().map(e -> e.decision()).toList();
    assertThat(decisions).contains(AuditDecision.PENDING, AuditDecision.APPROVED);
  }

  @Test
  void reject_after_approve_throws_and_approve_after_reject_throws() {
    var parked = (GuardResult.AwaitingApproval) call("write", "{\"a\":2}");
    f.approvals.approve(parked.decision().id(), "alice");
    assertThatThrownBy(() -> f.approvals.reject(parked.decision().id(), "bob"))
        .isInstanceOf(IllegalDecisionTransitionException.class);

    var parked2 = (GuardResult.AwaitingApproval) call("write", "{\"a\":3}");
    f.approvals.reject(parked2.decision().id(), "bob");
    assertThatThrownBy(() -> f.approvals.approve(parked2.decision().id(), "alice"))
        .isInstanceOf(IllegalDecisionTransitionException.class);
    assertThat(writes).hasValue(1);
    // agent re-calling a rejected call gets a structured rejection
    assertThat(call("write", "{\"a\":3}").toModelText())
        .contains("AG-APPROVAL-005")
        .contains("bob");
  }

  @Test
  void pending_decision_expires_after_ttl_and_can_be_parked_again() {
    var parked = (GuardResult.AwaitingApproval) call("write", "{\"a\":4}");
    f.clock.advance(Duration.ofHours(2));
    assertThat(f.approvals.find(parked.decision().id()).orElseThrow().state())
        .isEqualTo(DecisionState.EXPIRED);
    assertThatThrownBy(() -> f.approvals.approve(parked.decision().id(), "alice"))
        .isInstanceOf(IllegalDecisionTransitionException.class);
    var again = call("write", "{\"a\":4}");
    assertThat(again).isInstanceOf(GuardResult.AwaitingApproval.class);
    assertThat(((GuardResult.AwaitingApproval) again).decision().id())
        .isNotEqualTo(parked.decision().id());
    assertThat(f.auditSink.latest(10).stream().map(e -> e.decision()).toList())
        .contains(AuditDecision.EXPIRED);
  }

  @Test
  void tampered_arguments_between_approval_and_execution_are_refused() {
    var parked = (GuardResult.AwaitingApproval) call("write", "{\"a\":5}");
    var d = parked.decision();
    var tampered =
        new PendingDecision(
            d.id(),
            d.principal(),
            d.tool(),
            "{\"a\":999}",
            d.argsHash(),
            d.argsPreview(),
            d.conversationId(),
            d.correlationId(),
            d.createdAt(),
            d.expiresAt(),
            d.state(),
            null,
            null,
            false,
            null);
    f.decisions.save(tampered);
    assertThatThrownBy(() -> f.approvals.approve(d.id(), "alice"))
        .isInstanceOf(ArgumentsTamperedException.class);
    assertThat(writes).hasValue(0);
  }

  @Test
  void tool_failure_becomes_structured_error_and_is_audited_failed() {
    var r =
        f.guard.execute(
            ToolInvocation.of(AGENT, "read", "{}"),
            Optional.empty(),
            a -> {
              throw new IllegalStateException("db down");
            });
    assertThat(r).isInstanceOf(GuardResult.Failed.class);
    assertThat(r.toModelText()).contains("TOOL_FAILED").contains("db down").doesNotContain("\tat ");
    assertThat(f.auditSink.latest(1).get(0).decision()).isEqualTo(AuditDecision.FAILED);
  }

  @Test
  void anonymous_principal_is_denied_role_restricted_tools() {
    var r =
        f.guard.execute(
            ToolInvocation.of(Principal.anonymous(), "write", "{}"), Optional.empty(), a -> "x");
    assertThat(r).isInstanceOf(GuardResult.Denied.class);
  }

  @Test
  void audit_chain_stays_intact_across_the_flow() {
    call("read", "{}");
    var parked = (GuardResult.AwaitingApproval) call("write", "{\"a\":6}");
    f.approvals.approve(parked.decision().id(), "alice");
    call("admin_only", "{}");
    var report = new AuditChainVerifier(f.auditSink).verify();
    assertThat(report.intact()).isTrue();
    assertThat(report.verified()).isEqualTo(4);
  }
}

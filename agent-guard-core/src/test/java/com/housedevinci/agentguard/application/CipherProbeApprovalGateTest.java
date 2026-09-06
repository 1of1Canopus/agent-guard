package com.housedevinci.agentguard.application;

import static com.housedevinci.agentguard.application.GuardFixture.AGENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.domain.ArgumentsTamperedException;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.BudgetKind;
import com.housedevinci.agentguard.domain.BudgetLimit;
import com.housedevinci.agentguard.domain.BudgetScope;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * the security review security probes for the approval gate (branch feat/agent-guard-core). Each test documents
 * a behaviour the review reports on; a probe that starts failing means the behaviour was fixed and
 * the review entry can be closed.
 */
class CipherProbeApprovalGateTest {

  private final GuardFixture f = new GuardFixture();

  @BeforeEach
  void policies() {
    f.registry.register(
        "write", new PolicyRule(Set.of("AGENT"), Set.of(), Set.of(), SideEffect.WRITE));
    f.registry.register("read", PolicyRule.unrestricted(SideEffect.READ));
  }

  private GuardResult exec(Principal p, String tool, String args, ToolExecutor executor) {
    return f.guard.execute(ToolInvocation.of(p, tool, args), Optional.empty(), executor);
  }

  @Test
  void probe_executor_registry_is_keyed_by_tool_name_so_resume_runs_the_last_callers_closure() {
    var agentA = new Principal("agent-a", Set.of("AGENT"), Set.of(), "acme");
    var agentB = new Principal("agent-b", Set.of("AGENT"), Set.of(), "globex");
    List<String> ran = new ArrayList<>();

    var parkedA =
        (GuardResult.AwaitingApproval)
            exec(
                agentA,
                "write",
                "{\"order\":1}",
                args -> {
                  ran.add("closure-of-agent-a");
                  return "ok";
                });
    exec(
        agentB,
        "write",
        "{\"order\":2}",
        args -> {
          ran.add("closure-of-agent-b");
          return "ok";
        });

    var outcome = f.approvals.approve(parkedA.decision().id(), "approver");

    assertThat(outcome.result()).isInstanceOf(GuardResult.Executed.class);
    // agent-a's approved call executed through agent-b's captured closure (its exchange /
    // ToolContext / session)
    assertThat(ran).containsExactly("closure-of-agent-b");
  }

  @Test
  void probe_same_principal_id_in_another_tenant_receives_the_other_tenants_stored_result() {
    var adminT1 = new Principal("admin", Set.of("AGENT"), Set.of(), "tenant-1");
    var adminT2 = new Principal("admin", Set.of("AGENT"), Set.of(), "tenant-2");
    var executions = new AtomicInteger();
    String args = "{\"projectId\":7}";

    var parked =
        (GuardResult.AwaitingApproval)
            exec(
                adminT1,
                "write",
                args,
                a -> {
                  executions.incrementAndGet();
                  return "confidential result of tenant-1";
                });
    f.approvals.approve(parked.decision().id(), "approver-of-tenant-1");

    var r =
        exec(
            adminT2,
            "write",
            args,
            a -> {
              executions.incrementAndGet();
              return "result of tenant-2";
            });

    assertThat(r).isInstanceOf(GuardResult.Executed.class);
    assertThat(r.toModelText()).isEqualTo("confidential result of tenant-1");
    assertThat(executions).hasValue(1);
    assertThat(f.notified).hasSize(1); // tenant-2 never got a decision of its own
  }

  @Test
  void probe_parking_is_not_budgeted_so_pending_decisions_and_notifications_are_unbounded() {
    var fx =
        new GuardFixture(
            UnregisteredToolBehaviour.DENY,
            List.of(
                new BudgetLimit(
                    BudgetScope.PRINCIPAL, BudgetKind.TOOL_CALLS, Duration.ofMinutes(1), 3)));
    fx.registry.register(
        "write", new PolicyRule(Set.of("AGENT"), Set.of(), Set.of(), SideEffect.WRITE));
    for (int i = 0; i < 50; i++) {
      var r =
          fx.guard.execute(
              ToolInvocation.of(AGENT, "write", "{\"i\":" + i + "}"), Optional.empty(), a -> "x");
      assertThat(r).isInstanceOf(GuardResult.AwaitingApproval.class);
    }
    assertThat(fx.notified).hasSize(50);
    assertThat(fx.decisions.findByState(DecisionState.PENDING, 1000)).hasSize(50);
  }

  @Test
  void probe_approver_identity_and_time_are_absent_from_the_hash_chained_audit() {
    var parked = (GuardResult.AwaitingApproval) exec(AGENT, "write", "{\"a\":1}", a -> "ok");
    f.approvals.approve(parked.decision().id(), "alice-the-approver");

    List<AuditEvent> rows = f.auditSink.latest(10);
    assertThat(rows)
        .extracting(AuditEvent::decision)
        .contains(com.housedevinci.agentguard.domain.AuditDecision.APPROVED);
    assertThat(rows).extracting(AuditEvent::principalId).containsOnly("agent-1");
    assertThat(rows.stream().map(AuditChain::canonical))
        .noneMatch(c -> c.contains("alice-the-approver"));
  }

  @Test
  void probe_preview_truncation_hides_trailing_keys_from_the_approver() {
    String args =
        "{\"to\":\"cfo@corp.example\",\"body\":\""
            + "x".repeat(520)
            + "\",\"bcc\":\"attacker@evil.example\"}";
    var parked = (GuardResult.AwaitingApproval) exec(AGENT, "write", args, a -> "sent");
    var d = parked.decision();
    assertThat(d.argumentsJson()).contains("attacker@evil.example");
    assertThat(d.argsPreview()).doesNotContain("bcc").endsWith("...[truncated]");
  }

  @Test
  void probe_self_approval_is_accepted() {
    var parked = (GuardResult.AwaitingApproval) exec(AGENT, "write", "{\"a\":2}", a -> "ok");
    var outcome = f.approvals.approve(parked.decision().id(), AGENT.id());
    assertThat(outcome.result()).isInstanceOf(GuardResult.Executed.class);
    assertThat(outcome.decision().decidedBy()).isEqualTo(parked.decision().principal().id());
  }

  @Test
  void probe_tamper_detection_leaves_no_audit_row() {
    var parked = (GuardResult.AwaitingApproval) exec(AGENT, "write", "{\"a\":5}", a -> "ok");
    var d = parked.decision();
    f.decisions.save(
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
            null));
    int before = f.auditSink.latest(100).size();
    assertThatThrownBy(() -> f.approvals.approve(d.id(), "alice"))
        .isInstanceOf(ArgumentsTamperedException.class);
    assertThat(f.auditSink.latest(100)).hasSize(before);
    // and the decision is left APPROVED, not executed: approvable again by nobody, resumable later
    assertThat(f.decisions.findById(d.id()).orElseThrow().state())
        .isEqualTo(DecisionState.APPROVED);
  }

  @Test
  void probe_conversation_budget_is_skipped_without_an_id_and_reset_by_rotating_it() {
    var fx =
        new GuardFixture(
            UnregisteredToolBehaviour.DENY,
            List.of(
                new BudgetLimit(
                    BudgetScope.CONVERSATION, BudgetKind.STEPS, Duration.ofHours(1), 2)));
    fx.registry.register("read", PolicyRule.unrestricted(SideEffect.READ));
    for (int i = 0; i < 5; i++) {
      var r =
          fx.guard.execute(
              new ToolInvocation(AGENT, "read", "{}", null, null), Optional.empty(), a -> "x");
      assertThat(r).isInstanceOf(GuardResult.Executed.class);
    }
    for (int i = 0; i < 5; i++) {
      var r =
          fx.guard.execute(
              new ToolInvocation(AGENT, "read", "{}", "conv-" + i, null),
              Optional.empty(),
              a -> "x");
      assertThat(r).isInstanceOf(GuardResult.Executed.class);
    }
    // control: a stable conversation id is limited as configured
    GuardResult last = null;
    for (int i = 0; i < 3; i++) {
      last =
          fx.guard.execute(
              new ToolInvocation(AGENT, "read", "{}", "stable", null), Optional.empty(), a -> "x");
    }
    assertThat(last).isInstanceOf(GuardResult.BudgetExceeded.class);
  }

  @Test
  void probe_policy_tightened_after_parking_is_not_rechecked_at_resume() {
    var parked = (GuardResult.AwaitingApproval) exec(AGENT, "write", "{\"a\":3}", a -> "ok");
    f.registry.register(
        "write", new PolicyRule(Set.of("ADMIN"), Set.of(), Set.of(), SideEffect.WRITE));
    var outcome = f.approvals.approve(parked.decision().id(), "alice");
    assertThat(outcome.result()).isInstanceOf(GuardResult.Executed.class);
  }

  @Test
  void probe_an_approved_decision_answers_identical_calls_with_the_stale_result_forever() {
    var executions = new AtomicInteger();
    ToolExecutor ex =
        a -> {
          executions.incrementAndGet();
          return "refunded at " + f.clock.instant();
        };
    var parked = (GuardResult.AwaitingApproval) exec(AGENT, "write", "{\"order\":42}", ex);
    f.approvals.approve(parked.decision().id(), "alice");
    f.clock.advance(Duration.ofDays(30));
    var r = exec(AGENT, "write", "{\"order\":42}", ex);
    assertThat(r).isInstanceOf(GuardResult.Executed.class);
    assertThat(r.toModelText()).contains("2026-09-06T10:00:00Z");
    assertThat(executions).hasValue(1);
    assertThat(f.notified).hasSize(1);
  }
}

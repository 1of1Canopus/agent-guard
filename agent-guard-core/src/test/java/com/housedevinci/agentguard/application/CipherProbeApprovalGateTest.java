package com.housedevinci.agentguard.application;

import static com.housedevinci.agentguard.application.GuardFixture.AGENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.domain.ApprovalHashMismatchException;
import com.housedevinci.agentguard.domain.ArgumentRedactor;
import com.housedevinci.agentguard.domain.ArgumentsTamperedException;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditDecision;
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
 * Cipher security probes for the approval gate. H1, M1, M3, M4, M5 are flipped (they now assert the
 * fixed behaviour); the LOW probes (L1–L4) still document open items.
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

  @Test // H1 flipped
  void resume_runs_the_closure_captured_when_that_decision_was_parked() {
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
    assertThat(ran).containsExactly("closure-of-agent-a");
    assertThat(f.executors.find(parkedA.decision().id())).isEmpty(); // released after the run
  }

  @Test // M4 flipped (tenant in the dedup key)
  void same_principal_id_in_another_tenant_gets_its_own_decision() {
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
    assertThat(r).isInstanceOf(GuardResult.AwaitingApproval.class);
    assertThat(r.toModelText()).doesNotContain("tenant-1");
    assertThat(executions).hasValue(1);
    assertThat(f.notified).hasSize(2);
  }

  @Test // M4 flipped (parking is budgeted and capped)
  void parking_is_budgeted_and_capped_per_principal() {
    var fx =
        new GuardFixture(
            UnregisteredToolBehaviour.DENY,
            List.of(
                new BudgetLimit(
                    BudgetScope.PRINCIPAL, BudgetKind.TOOL_CALLS, Duration.ofMinutes(1), 3)));
    fx.registry.register(
        "write", new PolicyRule(Set.of("AGENT"), Set.of(), Set.of(), SideEffect.WRITE));
    int parked = 0;
    int refused = 0;
    for (int i = 0; i < 50; i++) {
      var r =
          fx.guard.execute(
              ToolInvocation.of(AGENT, "write", "{\"i\":" + i + "}"), Optional.empty(), a -> "x");
      if (r instanceof GuardResult.AwaitingApproval) {
        parked++;
      } else {
        assertThat(r).isInstanceOf(GuardResult.BudgetExceeded.class);
        refused++;
      }
    }
    assertThat(parked).isEqualTo(3);
    assertThat(refused).isEqualTo(47);
    assertThat(fx.notified).hasSize(3);

    // and without any budget, the pending cap holds
    var capped = new GuardFixture();
    capped.approvalLimits = new ApprovalLimits(5, 1024);
    capped.build();
    capped.registry.register("write", PolicyRule.unrestricted(SideEffect.WRITE));
    for (int i = 0; i < 5; i++) {
      assertThat(
              capped.guard.execute(
                  ToolInvocation.of(AGENT, "write", "{\"i\":" + i + "}"),
                  Optional.empty(),
                  a -> "x"))
          .isInstanceOf(GuardResult.AwaitingApproval.class);
    }
    var sixth =
        capped.guard.execute(
            ToolInvocation.of(AGENT, "write", "{\"i\":99}"), Optional.empty(), a -> "x");
    assertThat(sixth.toModelText()).contains("AG-APPROVAL-008");
    var huge =
        capped.guard.execute(
            ToolInvocation.of(AGENT, "write", "{\"blob\":\"" + "x".repeat(2000) + "\"}"),
            Optional.empty(),
            a -> "x");
    assertThat(huge.toModelText()).contains("AG-APPROVAL-009");
    assertThat(capped.decisions.findByState(DecisionState.PENDING, 100)).hasSize(5);
  }

  @Test // M1 flipped
  void approver_identity_is_part_of_the_hash_chained_audit() {
    var parked = (GuardResult.AwaitingApproval) exec(AGENT, "write", "{\"a\":1}", a -> "ok");
    f.approvals.approve(parked.decision().id(), "alice-the-approver");

    List<AuditEvent> rows = f.auditSink.latest(10);
    var approved =
        rows.stream().filter(e -> e.decision() == AuditDecision.APPROVED).findFirst().orElseThrow();
    assertThat(approved.actorId()).isEqualTo("alice-the-approver");
    assertThat(approved.principalId()).isEqualTo("agent-1");
    assertThat(AuditChain.canonical(approved)).contains("alice-the-approver");
    assertThat(
            AuditChain.verify(
                approved.withChain(approved.prevHash(), approved.hash()), approved.prevHash()))
        .isTrue();
    var forged =
        new AuditEvent(
            approved.sequence(),
            approved.timestamp(),
            approved.principalId(),
            approved.tenantId(),
            approved.tool(),
            approved.argsHash(),
            approved.resultHash(),
            approved.latencyMillis(),
            approved.decision(),
            approved.correlationId(),
            approved.decisionId(),
            "mallory",
            approved.prevHash(),
            approved.hash());
    assertThat(AuditChain.verify(forged, approved.prevHash())).isFalse();

    var parked2 = (GuardResult.AwaitingApproval) exec(AGENT, "write", "{\"a\":2}", a -> "ok");
    f.approvals.reject(parked2.decision().id(), "bob-the-rejecter");
    assertThat(f.auditSink.latest(1).get(0).actorId()).isEqualTo("bob-the-rejecter");
  }

  @Test // M5 flipped
  void approver_sees_the_full_redacted_arguments_and_attests_their_hash() {
    String args =
        "{\"to\":\"cfo@corp.example\",\"password\":\"hunter2\",\"body\":\""
            + "x".repeat(520)
            + "\",\"bcc\":\"attacker@evil.example\"}";
    var parked = (GuardResult.AwaitingApproval) exec(AGENT, "write", args, a -> "sent");
    var d = parked.decision();
    // the list preview is still capped (log safety) ...
    assertThat(d.argsPreview()).endsWith("...[truncated]");
    // ... but the full redacted form the approver fetches shows every key and no secret
    var full = ArgumentRedactor.defaults().redact(d.argumentsJson());
    assertThat(full)
        .contains("\"bcc\":\"attacker@evil.example\"")
        .doesNotContain("hunter2")
        .doesNotContain("[truncated]");
    // the approval binds what was reviewed to what runs
    assertThatThrownBy(() -> f.approvals.approve(d.id(), "alice", "0".repeat(64)))
        .isInstanceOf(ApprovalHashMismatchException.class);
    assertThat(f.decisions.findById(d.id()).orElseThrow().state()).isEqualTo(DecisionState.PENDING);
    assertThat(f.approvals.approve(d.id(), "alice", d.argsHash()).result())
        .isInstanceOf(GuardResult.Executed.class);
  }

  @Test // M3 flipped (core side): no conversation id = fail closed; rotation still capped per id
  void conversation_budget_denies_without_an_id() {
    var fx =
        new GuardFixture(
            UnregisteredToolBehaviour.DENY,
            List.of(
                new BudgetLimit(
                    BudgetScope.CONVERSATION, BudgetKind.STEPS, Duration.ofHours(1), 2)));
    fx.registry.register("read", PolicyRule.unrestricted(SideEffect.READ));
    var r =
        fx.guard.execute(
            new ToolInvocation(AGENT, "read", "{}", null, null), Optional.empty(), a -> "x");
    assertThat(r).isInstanceOf(GuardResult.Denied.class);
    assertThat(r.toModelText()).contains("AG-BUDGET-002");
    GuardResult last = null;
    for (int i = 0; i < 3; i++) {
      last =
          fx.guard.execute(
              new ToolInvocation(AGENT, "read", "{}", "stable", null), Optional.empty(), a -> "x");
    }
    assertThat(last).isInstanceOf(GuardResult.BudgetExceeded.class);
  }

  // ---- LOW items, still open: these document the current behaviour -------------------------

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
    assertThat(f.decisions.findById(d.id()).orElseThrow().state())
        .isEqualTo(DecisionState.APPROVED);
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

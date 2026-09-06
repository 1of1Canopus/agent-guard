package com.housedevinci.agentguard.application;

import static com.housedevinci.agentguard.application.GuardFixture.AGENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.domain.BudgetExceededException;
import com.housedevinci.agentguard.domain.BudgetKind;
import com.housedevinci.agentguard.domain.BudgetLimit;
import com.housedevinci.agentguard.domain.BudgetScope;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.SideEffect;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class BudgetEnforcerTest {

  private static final BudgetLimit THREE_CALLS =
      new BudgetLimit(BudgetScope.PRINCIPAL, BudgetKind.TOOL_CALLS, Duration.ofMinutes(1), 3);

  @Test
  void fourth_call_in_window_is_blocked_with_structured_error_and_audited() {
    var f = new GuardFixture(UnregisteredToolBehaviour.ALLOW, List.of(THREE_CALLS));
    var executed = new AtomicInteger();
    for (int i = 0; i < 3; i++) {
      var r = f.guard.execute(ToolInvocation.of(AGENT, "t", "{}"), Optional.empty(), a -> {
        executed.incrementAndGet();
        return "ok";
      });
      assertThat(r).isInstanceOf(GuardResult.Executed.class);
    }
    var fourth = f.guard.execute(ToolInvocation.of(AGENT, "t", "{}"), Optional.empty(), a -> {
      executed.incrementAndGet();
      return "ok";
    });
    assertThat(fourth).isInstanceOf(GuardResult.BudgetExceeded.class);
    assertThat(fourth.toModelText()).contains("BUDGET_EXCEEDED").contains("AG-BUDGET-001");
    assertThat(executed).hasValue(3);
    assertThat(f.auditSink.latest(1).get(0).decision().name()).isEqualTo("BUDGET_EXCEEDED");
  }

  @Test
  void window_rolls_over() {
    var f = new GuardFixture(UnregisteredToolBehaviour.ALLOW, List.of(THREE_CALLS));
    var enforcer = f.guard.budgets();
    var inv = ToolInvocation.of(AGENT, "t", "{}");
    enforcer.reserve(inv);
    enforcer.reserve(inv);
    enforcer.reserve(inv);
    assertThatThrownBy(() -> enforcer.reserve(inv)).isInstanceOf(BudgetExceededException.class);
    f.clock.advance(Duration.ofMinutes(1));
    enforcer.reserve(inv);
  }

  @Test
  void tenant_and_conversation_scopes_apply_only_when_subject_is_known() {
    var tenantLimit = new BudgetLimit(BudgetScope.TENANT, BudgetKind.TOOL_CALLS, Duration.ofHours(1), 1);
    var stepLimit = new BudgetLimit(BudgetScope.CONVERSATION, BudgetKind.STEPS, Duration.ofHours(1), 2);
    var f = new GuardFixture(UnregisteredToolBehaviour.ALLOW, List.of(tenantLimit, stepLimit));
    var enforcer = f.guard.budgets();

    var noTenant = new com.housedevinci.agentguard.domain.Principal("p", java.util.Set.of(), java.util.Set.of(), null);
    enforcer.reserve(ToolInvocation.of(noTenant, "t", "{}"));
    enforcer.reserve(ToolInvocation.of(noTenant, "t", "{}")); // tenant limit skipped, no conversation

    var conv = new ToolInvocation(noTenant, "t", "{}", "conv-1", null);
    enforcer.reserve(conv);
    enforcer.reserve(conv);
    assertThatThrownBy(() -> enforcer.reserve(conv)).isInstanceOf(BudgetExceededException.class);

    enforcer.reserve(ToolInvocation.of(AGENT, "t", "{}"));
    assertThatThrownBy(() -> enforcer.reserve(ToolInvocation.of(AGENT, "t", "{}")))
        .isInstanceOf(BudgetExceededException.class)
        .hasMessageContaining("TENANT");
  }

  @Test
  void token_budget_is_checked_before_and_recorded_after() {
    var tokens = new BudgetLimit(BudgetScope.PRINCIPAL, BudgetKind.TOKENS, Duration.ofDays(1), 1000);
    var f = new GuardFixture(UnregisteredToolBehaviour.ALLOW, List.of(tokens));
    var enforcer = f.guard.budgets();
    var inv = ToolInvocation.of(AGENT, "t", "{}");
    enforcer.reserve(inv);
    enforcer.recordTokens(AGENT, null, 999);
    enforcer.reserve(inv);
    enforcer.recordTokens(AGENT, null, 1);
    assertThatThrownBy(() -> enforcer.reserve(inv)).isInstanceOf(BudgetExceededException.class);
    enforcer.recordTokens(AGENT, null, -5); // ignored
  }

  @Test
  void concurrent_virtual_threads_cannot_exceed_the_budget() throws Exception {
    var f = new GuardFixture(UnregisteredToolBehaviour.ALLOW, List.of(THREE_CALLS));
    var executed = new AtomicInteger();
    try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
      var futures = new java.util.ArrayList<Future<GuardResult>>();
      for (int i = 0; i < 200; i++) {
        futures.add(pool.submit(() -> f.guard.execute(ToolInvocation.of(AGENT, "t", "{}"), Optional.empty(), a -> {
          executed.incrementAndGet();
          return "ok";
        })));
      }
      long ok = 0;
      for (var fut : futures) {
        if (fut.get() instanceof GuardResult.Executed) {
          ok++;
        }
      }
      assertThat(ok).isEqualTo(3);
    }
    assertThat(executed).hasValue(3);
    assertThat(new AuditChainVerifier(f.auditSink).verify().intact()).isTrue();
  }

  @Test
  void approved_calls_also_consume_budget() {
    var f = new GuardFixture(UnregisteredToolBehaviour.ALLOW, List.of(new BudgetLimit(BudgetScope.PRINCIPAL, BudgetKind.TOOL_CALLS, Duration.ofMinutes(1), 1)));
    f.registry.register("write", PolicyRule.unrestricted(SideEffect.WRITE));
    f.guard.execute(ToolInvocation.of(AGENT, "t", "{}"), Optional.empty(), a -> "ok");
    var parked = (GuardResult.AwaitingApproval) f.guard.execute(ToolInvocation.of(AGENT, "write", "{}"), Optional.empty(), a -> "written");
    var outcome = f.approvals.approve(parked.decision().id(), "alice");
    assertThat(outcome.result()).isInstanceOf(GuardResult.BudgetExceeded.class);
  }
}

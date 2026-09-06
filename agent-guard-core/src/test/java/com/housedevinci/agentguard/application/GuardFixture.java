package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.adapter.memory.InMemoryBudgetStore;
import com.housedevinci.agentguard.adapter.memory.InMemoryDecisionStore;
import com.housedevinci.agentguard.domain.ArgumentRedactor;
import com.housedevinci.agentguard.domain.BudgetLimit;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.ToolPolicyEvaluator;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Wires the whole application layer over in-memory adapters with a mutable clock. */
final class GuardFixture {

  static final Principal AGENT = new Principal("agent-1", Set.of("AGENT"), Set.of(), "acme");

  final MutableClock clock = new MutableClock(Instant.parse("2026-09-06T10:00:00Z"));
  final ToolPolicyRegistry registry = new ToolPolicyRegistry();
  final InMemoryDecisionStore decisions = new InMemoryDecisionStore();
  final InMemoryAuditSink auditSink = new InMemoryAuditSink();
  final InMemoryBudgetStore budgetStore = new InMemoryBudgetStore(clock);
  final ToolExecutorRegistry executors = new ToolExecutorRegistry();
  final List<PendingDecision> notified = new ArrayList<>();
  final AuditRecorder audit = new AuditRecorder(auditSink, clock);
  final UnregisteredToolBehaviour unregistered;
  final List<BudgetLimit> limits;

  ToolGuard guard;
  ApprovalService approvals;

  GuardFixture() {
    this(UnregisteredToolBehaviour.DENY, List.of());
  }

  GuardFixture(UnregisteredToolBehaviour unregistered, List<BudgetLimit> limits) {
    this.unregistered = unregistered;
    this.limits = limits;
    build();
  }

  void build() {
    var budgets = new BudgetEnforcer(limits, budgetStore, clock);
    var resumer = new DecisionResumer(decisions, executors, budgets, audit, clock);
    approvals =
        new ApprovalService(decisions, notified::add, resumer, audit, clock, Duration.ofHours(1));
    guard =
        new ToolGuard(
            new PolicyLookup(registry, unregistered),
            ToolPolicyEvaluator.defaults(),
            budgets,
            approvals,
            resumer,
            decisions,
            executors,
            audit,
            ArgumentRedactor.defaults(),
            clock);
  }

  static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant start) {
      this.now = start;
    }

    void advance(Duration d) {
      now = now.plus(d);
    }

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}

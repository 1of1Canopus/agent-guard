package com.housedevinci.agentguard.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * Cipher probes for the clean-verdict pass on {@code 50ed8d3}, application layer: the ordering the
 * canonical-hash fix introduced, the four-eyes comparison, and the keyed audit chain on a trail
 * that predates the key. Each probe asserts today's behaviour; the fix flips it.
 */
class CipherProbeCleanGuardTest {

  /**
   * C4: {@code ToolGuard.gate} canonicalises (parses) the arguments to compute the dedup hash
   * <em>before</em> the {@code maxArgumentBytes} check, so the cap no longer bounds the work the
   * guard does on model-supplied text. Measured on this machine: 4 MB of JSON becomes ~163 MB of
   * live nodes in ~230 ms — a ~40x amplification that the 64 KB default cap was there to prevent.
   *
   * <p>Fix: move the {@code maxArgumentBytes} check to the top of {@code gate} (and apply the same
   * cap on the ALLOW path in {@code dispatch} before anything hashes or previews the arguments).
   */
  @Test
  void the_size_cap_refuses_arguments_before_they_are_parsed() {
    var f = new GuardFixture();
    f.registry.register(
        "write", new PolicyRule(Set.of("AGENT"), Set.of(), Set.of(), SideEffect.WRITE));
    f.options = new GuardOptions(20, 32, Duration.ofHours(1), false); // 32-byte cap
    var seen = new AtomicReference<String>();
    var spy = new RecordingDecisionStore(f.decisions, seen);
    var guard =
        new ToolGuard(
            new PolicyLookup(f.registry, UnregisteredToolBehaviour.DENY),
            com.housedevinci.agentguard.domain.ToolPolicyEvaluator.defaults(),
            new BudgetEnforcer(List.of(), f.budgetStore, f.clock, MissingSubjectPolicy.DENY),
            f.approvals,
            new DecisionResumer(
                f.decisions,
                f.executors,
                f.audit,
                ResumeContextProvider.none(),
                new PolicyLookup(f.registry, UnregisteredToolBehaviour.DENY),
                com.housedevinci.agentguard.domain.ToolPolicyEvaluator.defaults(),
                PrincipalRefresher.identity(),
                false,
                f.clock),
            spy,
            f.executors,
            f.audit,
            com.housedevinci.agentguard.domain.ArgumentRedactor.defaults(),
            f.options,
            f.clock);

    String oversized = "{\"a\":\"" + "x".repeat(4096) + "\"}"; // far over the 32-byte cap
    var result =
        guard.execute(
            ToolInvocation.of(GuardFixture.AGENT, "write", oversized),
            Optional.empty(),
            i -> "never");

    assertThat(result).isInstanceOf(GuardResult.Denied.class);
    assertThat(((GuardResult.Denied) result).code())
        .isEqualTo(com.housedevinci.agentguard.domain.ErrorCodes.APPROVAL_ARGS_TOO_LARGE);
    // the size cap now runs first: the dedup lookup (which parses via ArgumentCanonicalizer.hash)
    // never ran
    assertThat(seen.get()).isNull();
  }

  /**
   * C5: four-eyes compares the approver id with {@code equals}, so on any identity provider that
   * treats logins case-insensitively (LDAP, e-mail logins, Keycloak's default username handling)
   * the agent's own operator approves their own parked call by logging in with a different casing.
   *
   * <p>Fix: compare {@code approver.strip()} against {@code decision.principal().id().strip()} with
   * {@code equalsIgnoreCase} in {@code ApprovalService.fourEyes}.
   */
  @Test
  void four_eyes_rejects_a_differently_cased_approver_id() {
    var f = new GuardFixture();
    var agent = new Principal("alice", Set.of("AGENT"), Set.of(), "acme");
    var parked =
        f.approvals.park(
            ToolInvocation.of(agent, "refund", "{\"a\":1}"),
            new com.housedevinci.agentguard.domain.ToolRef("refund", SideEffect.WRITE),
            "preview");
    f.executors.register(parked.id(), i -> "ran");

    // same human, other casing: still self-approval
    assertThatThrownBy(() -> f.approvals.approve(parked.id(), "ALICE"))
        .isInstanceOf(com.housedevinci.agentguard.domain.SelfApprovalException.class);
    // and with a trailing space
    var parked2 =
        f.approvals.park(
            ToolInvocation.of(agent, "refund", "{\"a\":2}"),
            new com.housedevinci.agentguard.domain.ToolRef("refund", SideEffect.WRITE),
            "preview");
    f.executors.register(parked2.id(), i -> "ran");
    assertThatThrownBy(() -> f.approvals.approve(parked2.id(), "alice "))
        .isInstanceOf(com.housedevinci.agentguard.domain.SelfApprovalException.class);
  }

  /**
   * C6 (superseded by the keyed-from-birth design change): the original probe modelled "turning on
   * {@code agentguard.audit.hmac-secret} on a running installation" and required the existing
   * unkeyed trail to keep verifying INTACT. Under keyed-from-birth this is no longer the goal — a
   * trail is keyed from row 1 or unkeyed forever, and switching is refused, not accommodated. The
   * replacement lives in {@code CipherProbeAnchorKeyingJdbcTest
   * .a_keyed_instance_is_refused_on_a_trail_that_started_unkeyed}: restarting an installation with
   * the secret newly set fails at startup, naming {@code agentguard.audit.hmac-secret} and the
   * remedy (start a new trail).
   */

  /** Delegating store that records the dedup lookup the canonical hash feeds. */
  private record RecordingDecisionStore(
      com.housedevinci.agentguard.domain.DecisionStore delegate, AtomicReference<String> lastHash)
      implements com.housedevinci.agentguard.domain.DecisionStore {

    @Override
    public void save(PendingDecision decision) {
      delegate.save(decision);
    }

    @Override
    public Optional<PendingDecision> findById(DecisionId id) {
      return delegate.findById(id);
    }

    @Override
    public Optional<PendingDecision> findLatest(
        String principalId, String tenantId, String tool, String argsHash, Instant createdAfter) {
      lastHash.set(argsHash);
      return delegate.findLatest(principalId, tenantId, tool, argsHash, createdAfter);
    }

    @Override
    public long countPending(String principalId, String tenantId) {
      return delegate.countPending(principalId, tenantId);
    }

    @Override
    public List<PendingDecision> findByState(DecisionState state, String tenantId, int limit) {
      return delegate.findByState(state, tenantId, limit);
    }

    @Override
    public boolean transition(
        DecisionId id, DecisionState expected, DecisionState target, String by, Instant at) {
      return delegate.transition(id, expected, target, by, at);
    }

    @Override
    public boolean markExecutedOnce(DecisionId id) {
      return delegate.markExecutedOnce(id);
    }

    @Override
    public void storeResult(DecisionId id, String resultJson) {
      delegate.storeResult(id, resultJson);
    }
  }
}

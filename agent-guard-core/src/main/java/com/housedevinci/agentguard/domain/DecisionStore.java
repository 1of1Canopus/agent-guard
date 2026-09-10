package com.housedevinci.agentguard.domain;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Persistence port for parked decisions. Implementations must be safe under concurrent use. */
public interface DecisionStore {

  void save(PendingDecision decision);

  Optional<PendingDecision> findById(DecisionId id);

  /**
   * Latest decision for the same principal, tenant, tool and arguments. {@code tenantId} may be
   * null (single-tenant); a null tenant never matches a decision that has one.
   */
  Optional<PendingDecision> findLatest(
      String principalId, String tenantId, String tool, String argsHash, Instant createdAfter);

  /** Number of PENDING decisions parked by this principal in this tenant (null = no tenant). */
  long countPending(String principalId, String tenantId);

  /**
   * All tenants. Prefer {@link #findByState(DecisionState, String, int)} for a tenant-scoped
   * caller: filtering after this applies {@code limit} can hide a tenant's own pending work behind
   * a busier neighbour's (C10).
   */
  default List<PendingDecision> findByState(DecisionState state, int limit) {
    return findByState(state, null, limit);
  }

  /**
   * Same, restricted to one tenant ({@code null} = every tenant, for internal maintenance such as
   * expiring overdue decisions). The filter must apply before {@code limit}, not after (C10).
   */
  List<PendingDecision> findByState(DecisionState state, String tenantId, int limit);

  /**
   * Compare-and-set of the state: succeeds only if the stored state is {@code expected}.
   *
   * @return true if this call performed the transition
   */
  boolean transition(
      DecisionId id, DecisionState expected, DecisionState target, String by, Instant at);

  /**
   * Marks the decision executed if it never was (processed-event-ledger pattern).
   *
   * @return true if this call won the right to execute, false if it already ran
   */
  boolean markExecutedOnce(DecisionId id);

  void storeResult(DecisionId id, String resultJson);
}

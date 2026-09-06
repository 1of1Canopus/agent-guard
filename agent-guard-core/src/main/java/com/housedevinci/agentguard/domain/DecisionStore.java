package com.housedevinci.agentguard.domain;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Persistence port for parked decisions. Implementations must be safe under concurrent use. */
public interface DecisionStore {

  void save(PendingDecision decision);

  Optional<PendingDecision> findById(DecisionId id);

  /** Latest decision for the same principal, tool and arguments, newest first. */
  Optional<PendingDecision> findLatest(String principalId, String tool, String argsHash);

  List<PendingDecision> findByState(DecisionState state, int limit);

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

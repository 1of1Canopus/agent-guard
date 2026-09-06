package com.housedevinci.agentguard.domain;

import java.util.EnumSet;
import java.util.Set;

/**
 * Approval state machine. {@code PENDING} is the only non-terminal state; it may move to exactly
 * one of {@code APPROVED}, {@code REJECTED} or {@code EXPIRED}. Every other transition, including a
 * self transition, throws {@link IllegalDecisionTransitionException}.
 */
public enum DecisionState {
  PENDING,
  APPROVED,
  REJECTED,
  EXPIRED;

  private static final Set<DecisionState> FROM_PENDING = EnumSet.of(APPROVED, REJECTED, EXPIRED);

  public boolean isTerminal() {
    return this != PENDING;
  }

  public boolean canTransitionTo(DecisionState target) {
    return this == PENDING && FROM_PENDING.contains(target);
  }

  /**
   * Moves to {@code target}.
   *
   * @throws IllegalDecisionTransitionException when the transition is not allowed
   */
  public DecisionState transitionTo(DecisionState target) {
    if (!canTransitionTo(target)) {
      throw new IllegalDecisionTransitionException(this, target);
    }
    return target;
  }
}

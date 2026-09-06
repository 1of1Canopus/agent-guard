package com.housedevinci.agentguard.domain;

/** Thrown by {@link DecisionState#transitionTo} for any transition the state machine forbids. */
public final class IllegalDecisionTransitionException extends AgentGuardException {
  public IllegalDecisionTransitionException(DecisionState from, DecisionState to) {
    super(
        ErrorCodes.APPROVAL_ILLEGAL_TRANSITION,
        "Illegal decision transition " + from + " -> " + to);
  }
}

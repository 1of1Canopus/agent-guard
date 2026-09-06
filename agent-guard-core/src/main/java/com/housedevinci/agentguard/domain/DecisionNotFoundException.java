package com.housedevinci.agentguard.domain;

/** No decision with the given id. */
public final class DecisionNotFoundException extends AgentGuardException {
  public DecisionNotFoundException(DecisionId id) {
    super(ErrorCodes.APPROVAL_NOT_FOUND, "Decision not found: " + id.value());
  }
}

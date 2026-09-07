package com.housedevinci.agentguard.domain;

/** The arguments to execute no longer match the hash the human approved. */
public final class ArgumentsTamperedException extends AgentGuardException {
  public ArgumentsTamperedException(DecisionId id) {
    super(
        ErrorCodes.APPROVAL_ARGS_TAMPERED,
        "Arguments of decision " + id.value() + " do not match the approved hash");
  }
}

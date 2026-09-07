package com.housedevinci.agentguard.domain;

/** The approver attested a hash that is not the decision's arguments hash. */
public final class ApprovalHashMismatchException extends AgentGuardException {
  public ApprovalHashMismatchException(DecisionId id) {
    super(
        ErrorCodes.APPROVAL_HASH_MISMATCH,
        "Attested arguments hash does not match decision " + id.value());
  }
}

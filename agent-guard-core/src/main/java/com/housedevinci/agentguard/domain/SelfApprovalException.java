package com.housedevinci.agentguard.domain;

/** Four-eyes rule: the principal that parked a call may not approve or reject it. */
public final class SelfApprovalException extends AgentGuardException {
  public SelfApprovalException(DecisionId id, String approver) {
    super(
        ErrorCodes.APPROVAL_SELF,
        "'" + approver + "' parked decision " + id.value() + " and may not decide it");
  }
}

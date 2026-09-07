package com.housedevinci.agentguard.domain;

/** A configured budget scope has no subject for this call and the missing-subject policy denies. */
public final class BudgetSubjectMissingException extends AgentGuardException {
  private final BudgetLimit limit;

  public BudgetSubjectMissingException(BudgetLimit limit) {
    super(
        ErrorCodes.BUDGET_SUBJECT_MISSING,
        "Budget "
            + limit.kind()
            + " per "
            + limit.scope()
            + " is configured but the call carries no "
            + limit.scope().name().toLowerCase(java.util.Locale.ROOT)
            + " id");
    this.limit = limit;
  }

  public BudgetLimit limit() {
    return limit;
  }
}

package com.housedevinci.agentguard.domain;

/** A budget window is exhausted. Raised before the tool is dispatched. */
public final class BudgetExceededException extends AgentGuardException {
  private final BudgetLimit limit;
  private final long used;

  public BudgetExceededException(BudgetLimit limit, long used) {
    super(
        ErrorCodes.BUDGET_EXCEEDED,
        "Budget exceeded: "
            + limit.kind()
            + " per "
            + limit.scope()
            + " is "
            + limit.limit()
            + " per "
            + limit.window()
            + ", used "
            + used);
    this.limit = limit;
    this.used = used;
  }

  public BudgetLimit limit() {
    return limit;
  }

  public long used() {
    return used;
  }
}

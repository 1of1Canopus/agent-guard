package com.housedevinci.agentguard.domain;

/** The one rule of budgets (copied from the kit's UsageQuotaPolicy). */
public final class BudgetPolicy {
  private BudgetPolicy() {}

  public static boolean wouldExceed(long cap, long used, long requestedUnits) {
    return used + requestedUnits > cap;
  }
}

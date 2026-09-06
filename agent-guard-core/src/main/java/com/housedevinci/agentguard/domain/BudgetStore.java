package com.housedevinci.agentguard.domain;

import java.time.Duration;

/**
 * Counter store for budgets. {@link #incrementAndGet} must be atomic across concurrent callers;
 * entries may be dropped once {@code ttl} has elapsed.
 */
public interface BudgetStore {

  long incrementAndGet(String key, long amount, Duration ttl);

  long current(String key);
}

package com.housedevinci.agentguard.adapter.memory;

import com.housedevinci.agentguard.domain.BudgetStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Atomic in-memory counters with expiry. For tests and single-node development. */
public final class InMemoryBudgetStore implements BudgetStore {

  private record Entry(long value, Instant expiresAt) {}

  private final Map<String, Entry> counters = new ConcurrentHashMap<>();
  private final Clock clock;

  public InMemoryBudgetStore(Clock clock) {
    this.clock = clock;
  }

  @Override
  public long incrementAndGet(String key, long amount, Duration ttl) {
    var now = clock.instant();
    return counters
        .compute(
            key,
            (k, e) ->
                (e == null || !e.expiresAt().isAfter(now))
                    ? new Entry(amount, now.plus(ttl))
                    : new Entry(e.value() + amount, e.expiresAt()))
        .value();
  }

  @Override
  public long current(String key) {
    var e = counters.get(key);
    return (e == null || !e.expiresAt().isAfter(clock.instant())) ? 0 : e.value();
  }
}

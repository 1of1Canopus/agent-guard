package com.housedevinci.agentguard.adapter.redis;

import com.housedevinci.agentguard.domain.BudgetStore;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import redis.clients.jedis.UnifiedJedis;

/**
 * Redis counters through Jedis: {@code INCRBY} plus a {@code PEXPIRE} on first write, in one Lua
 * script so the pair is atomic.
 */
public final class JedisBudgetStore implements BudgetStore {

  private static final String SCRIPT =
      "local v = redis.call('INCRBY', KEYS[1], ARGV[1]) "
          + "if v == tonumber(ARGV[1]) then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end "
          + "return v";

  private final UnifiedJedis jedis;

  public JedisBudgetStore(UnifiedJedis jedis) {
    this.jedis = Objects.requireNonNull(jedis, "jedis");
  }

  @Override
  public long incrementAndGet(String key, long amount, Duration ttl) {
    Object result =
        jedis.eval(SCRIPT, List.of(key), List.of(Long.toString(amount), Long.toString(ttl.toMillis())));
    return ((Number) result).longValue();
  }

  @Override
  public long current(String key) {
    String v = jedis.get(key);
    return v == null ? 0L : Long.parseLong(v);
  }
}

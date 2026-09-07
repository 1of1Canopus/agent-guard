package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.redis.JedisBudgetStore;
import com.housedevinci.agentguard.domain.BudgetStore;
import java.net.URI;
import redis.clients.jedis.ConnectionPoolConfig;
import redis.clients.jedis.JedisPooled;

/**
 * Loaded only when {@code agentguard.budgets.store=REDIS}, so Jedis stays optional. The pool is
 * pre-filled from the (platform) startup thread so it never has to grow while virtual threads are
 * calling: commons-pool2's growth path holds a monitor around the Jedis handshake, which pins JDK
 * 21-23 virtual threads and can deadlock the JVM under a burst.
 */
final class JedisBudgetStoreFactory {
  private JedisBudgetStoreFactory() {}

  static ConnectionPoolConfig poolConfig(AgentGuardProperties.Pool pool) {
    var config = new ConnectionPoolConfig();
    config.setMaxTotal(pool.getMaxTotal());
    config.setMaxIdle(pool.getMaxTotal());
    config.setMinIdle(pool.effectiveMinIdle());
    config.setMaxWait(pool.getMaxWait());
    config.setBlockWhenExhausted(true);
    return config;
  }

  static BudgetStore create(URI uri, AgentGuardProperties.Pool pool) {
    var jedis = new JedisPooled(poolConfig(pool), uri);
    if (pool.isPreparePool()) {
      try {
        jedis.getPool().preparePool();
      } catch (Exception e) {
        jedis.close();
        throw new AgentGuardConfigurationException(
            "agentguard.redis.uri: cannot open the Redis connection pool: " + e.getMessage());
      }
    }
    if (pool.isPlatformThreads() && Runtime.version().feature() < 24) {
      // V5: worker-thread count and queue bound are their own properties, decoupled from
      // max-total (the Jedis connection pool size) — see AgentGuardProperties.Pool.
      return JedisBudgetStore.onPlatformThreads(
          jedis,
          pool.effectivePlatformThreadCount(),
          pool.effectivePlatformThreadQueueSize(),
          pool.getMaxWait());
    }
    return new JedisBudgetStore(jedis);
  }
}

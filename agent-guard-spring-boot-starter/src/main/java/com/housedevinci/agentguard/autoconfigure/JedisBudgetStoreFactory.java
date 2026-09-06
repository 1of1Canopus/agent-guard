package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.redis.JedisBudgetStore;
import com.housedevinci.agentguard.domain.BudgetStore;
import java.net.URI;
import redis.clients.jedis.JedisPooled;

/** Loaded only when {@code agentguard.budgets.store=REDIS}, so Jedis stays optional. */
final class JedisBudgetStoreFactory {
  private JedisBudgetStoreFactory() {}

  static BudgetStore create(URI uri) {
    return new JedisBudgetStore(new JedisPooled(uri.toString()));
  }
}

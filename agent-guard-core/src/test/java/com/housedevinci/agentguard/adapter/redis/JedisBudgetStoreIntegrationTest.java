package com.housedevinci.agentguard.adapter.redis;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import redis.clients.jedis.JedisPooled;

@Testcontainers
class JedisBudgetStoreIntegrationTest {

  @Container
  static final GenericContainer<?> REDIS =
      new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

  static JedisPooled jedis;

  @BeforeAll
  static void connect() {
    jedis = new JedisPooled(REDIS.getHost(), REDIS.getMappedPort(6379));
  }

  @AfterAll
  static void close() {
    jedis.close();
  }

  @Test
  void increments_atomically_and_sets_ttl_once() throws Exception {
    var store = new JedisBudgetStore(jedis);
    var key = "agentguard:budget:test:" + System.nanoTime();
    List<Long> seen = new ArrayList<>();
    // platform threads on purpose: Jedis pools borrow under synchronized, which pins JDK 21 virtual
    // threads and deadlocks once the carriers are exhausted (see SECURITY-NOTES.md, "Redis +
    // virtual threads").
    var pool = Executors.newFixedThreadPool(16);
    try {
      var futures = new ArrayList<Future<Long>>();
      for (int i = 0; i < 100; i++) {
        futures.add(pool.submit(() -> store.incrementAndGet(key, 1, Duration.ofMinutes(1))));
      }
      for (var f : futures) {
        seen.add(f.get());
      }
    } finally {
      pool.shutdownNow();
    }
    assertThat(seen).hasSize(100).doesNotHaveDuplicates().contains(1L, 100L);
    assertThat(store.current(key)).isEqualTo(100);
    assertThat(jedis.pttl(key)).isBetween(1L, 60_000L);
    assertThat(store.current("agentguard:budget:missing")).isZero();
  }

  @Test
  void expired_key_restarts_from_zero() throws Exception {
    var store = new JedisBudgetStore(jedis);
    var key = "agentguard:budget:short:" + System.nanoTime();
    assertThat(store.incrementAndGet(key, 2, Duration.ofMillis(200))).isEqualTo(2);
    Thread.sleep(400);
    assertThat(store.current(key)).isZero();
    assertThat(store.incrementAndGet(key, 1, Duration.ofMinutes(1))).isEqualTo(1);
  }
}

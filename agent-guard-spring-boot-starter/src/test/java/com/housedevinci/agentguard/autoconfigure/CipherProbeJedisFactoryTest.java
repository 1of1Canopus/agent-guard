package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * the security review re-verification of H3: the starter's factory (pre-filled pool, default size 8) under 200
 * virtual threads on a cold start, in-process with the default scheduler.
 */
@Testcontainers
class CipherProbeJedisFactoryTest {

  @Container
  static final GenericContainer<?> REDIS =
      new GenericContainer<>(
              "redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99")
          .withExposedPorts(6379);

  @Test
  void factory_pool_never_grows_under_virtual_thread_burst() throws Exception {
    burst(true);
  }

  @Test // R6 flipped: even a cold, growing pool completes because Redis calls run on platform
  // threads
  void factory_without_prefill_still_completes_under_virtual_threads() throws Exception {
    burst(false);
  }

  private static void burst(boolean prefill) throws Exception {
    int threads = 200;
    var pool = new AgentGuardProperties.Pool();
    pool.setPreparePool(prefill);
    // V5: max-total (the Jedis connection pool) stays small and contended, as H3/R6 intended —
    // the platform-thread pool and its bounded queue (C7) are sized from their own
    // properties, decoupled from max-total, so the burst does not have to inflate the connection
    // pool just to get enough workers to submit to
    pool.setMaxTotal(4);
    pool.setPlatformThreadCount(threads);
    pool.setPlatformThreadQueueSize(threads);
    var store =
        JedisBudgetStoreFactory.create(
            URI.create("redis://" + REDIS.getHost() + ":" + REDIS.getMappedPort(6379)), pool);
    var key = "the security review:factory:" + System.nanoTime();
    var start = new CountDownLatch(1);
    var done = new CountDownLatch(threads);
    var errors = new AtomicInteger();
    List<Thread> list = new ArrayList<>();
    for (int i = 0; i < threads; i++) {
      list.add(
          Thread.ofVirtual()
              .unstarted(
                  () -> {
                    try {
                      start.await();
                      for (int j = 0; j < 5; j++) {
                        store.incrementAndGet(key, 1, Duration.ofMinutes(1));
                      }
                    } catch (Exception e) {
                      errors.incrementAndGet();
                    } finally {
                      done.countDown();
                    }
                  }));
    }
    list.forEach(Thread::start);
    start.countDown();
    assertThat(done.await(20, TimeUnit.SECONDS)).as("all virtual threads finished").isTrue();
    assertThat(errors).hasValue(0);
    assertThat(store.current(key)).isEqualTo(1000);
    assertThat(
            ((com.housedevinci.agentguard.adapter.redis.JedisBudgetStore) store)
                .isOnPlatformThreads())
        .isEqualTo(Runtime.version().feature() < 24);
  }
}

package com.housedevinci.agentguard.adapter.redis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import redis.clients.jedis.UnifiedJedis;

/**
 * Cipher probes for the clean-verdict pass on {@code 50ed8d3}: the bounded platform-thread executor
 * the R6 fix introduced. No Redis is contacted — the pool thread is held by a foreign task, so the
 * store's own task never runs. Each probe asserts today's behaviour; the fix flips it.
 */
class CipherProbeCleanRedisTest {

  private static ThreadPoolExecutor executorOf(JedisBudgetStore store) throws Exception {
    var field = JedisBudgetStore.class.getDeclaredField("executor");
    field.setAccessible(true);
    return (ThreadPoolExecutor) (ExecutorService) field.get(store);
  }

  /**
   * C7: a Redis call that misses {@code maxWait} is abandoned, not cancelled, on a {@code
   * newFixedThreadPool} whose queue is unbounded. While Redis is slow every guarded tool call adds
   * one more task that nobody will ever wait for: the queue grows without bound (heap), and every
   * later call queues behind the backlog and times out too, so the guard fails closed for the whole
   * application long after Redis recovers.
   *
   * <p>Fix: {@code future.cancel(true)} on timeout, and build the pool as a {@code
   * ThreadPoolExecutor} with an {@code ArrayBlockingQueue(maxTotal)} plus an {@code AbortPolicy}
   * mapped to {@code AG-GUARD-001}, so a saturated pool refuses immediately instead of queueing.
   */
  @Test
  void probe_a_timed_out_redis_call_stays_queued_on_an_unbounded_queue() throws Exception {
    var store =
        JedisBudgetStore.onPlatformThreads(
            new UnifiedJedis("redis://127.0.0.1:1"), 1, Duration.ofMillis(50));
    var pool = executorOf(store);
    assertThat(pool.getQueue().remainingCapacity()).isEqualTo(Integer.MAX_VALUE);

    var hold = new CountDownLatch(1);
    var running = new CountDownLatch(1);
    pool.submit(
        () -> {
          running.countDown();
          hold.await(10, TimeUnit.SECONDS);
          return null;
        });
    assertThat(running.await(5, TimeUnit.SECONDS)).isTrue();

    for (int i = 0; i < 5; i++) {
      assertThatThrownBy(() -> store.current("budget-key"))
          .isInstanceOf(AgentGuardException.class)
          .extracting(e -> ((AgentGuardException) e).code())
          .isEqualTo(ErrorCodes.GUARD_UNAVAILABLE);
    }

    // every abandoned call is still queued and will run whenever Redis recovers
    assertThat(pool.getQueue()).hasSize(5);
    hold.countDown();
    pool.shutdownNow();
  }

  /**
   * C8: the executor is created per store and never shut down — {@link JedisBudgetStore} is not
   * {@code AutoCloseable} and the factory registers no destroy method, so every Spring context that
   * builds one leaks {@code agentguard-redis} threads (devtools restarts, {@code @DirtiesContext}
   * test suites, any app that closes and reopens a context).
   *
   * <p>Fix: implement {@code AutoCloseable} ({@code executor.shutdownNow()}), and let the bean
   * definition in {@code JedisBudgetStoreFactory}/{@code AgentGuardAutoConfiguration} pick it up.
   */
  @Test
  void probe_the_platform_thread_executor_is_never_shut_down() throws Exception {
    assertThat(AutoCloseable.class.isAssignableFrom(JedisBudgetStore.class)).isFalse();
    assertThat(Arrays.stream(JedisBudgetStore.class.getMethods()).map(m -> m.getName()))
        .doesNotContain("close", "shutdown", "destroy");

    var store =
        JedisBudgetStore.onPlatformThreads(
            new UnifiedJedis("redis://127.0.0.1:1"), 2, Duration.ofMillis(50));
    var pool = executorOf(store);
    pool.prestartAllCoreThreads();
    assertThat(Thread.getAllStackTraces().keySet())
        .anyMatch(t -> t.getName().startsWith("agentguard-redis") && t.isAlive());
    pool.shutdownNow(); // the probe cleans up after itself; production has nothing that does
  }
}

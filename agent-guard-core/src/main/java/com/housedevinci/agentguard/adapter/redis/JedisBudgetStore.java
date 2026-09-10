package com.housedevinci.agentguard.adapter.redis;

import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.BudgetStore;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import redis.clients.jedis.UnifiedJedis;

/**
 * Redis counters through Jedis: {@code INCRBY} plus a {@code PEXPIRE} on first write, in one Lua
 * script so the pair is atomic. On JDK 21-23 every Jedis call can run on a bounded pool of daemon
 * platform threads ({@link #onPlatformThreads}), so a virtual-thread caller never reaches the
 * connection pool's growth lock whatever happens to the connections (R6). The pool's queue is
 * bounded and a timed-out call is cancelled and removed from it (C7): while Redis is slow, calls
 * fail fast instead of piling up on an unbounded queue that outlives the outage. Closing the store
 * shuts the pool down (C8).
 */
public final class JedisBudgetStore implements BudgetStore, AutoCloseable {

  private static final String SCRIPT =
      "local v = redis.call('INCRBY', KEYS[1], ARGV[1]) "
          + "if v == tonumber(ARGV[1]) then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end "
          + "return v";

  private final UnifiedJedis jedis;
  private final ExecutorService executor;
  private final Duration maxWait;

  public JedisBudgetStore(UnifiedJedis jedis) {
    this(jedis, null, Duration.ofSeconds(2));
  }

  private JedisBudgetStore(UnifiedJedis jedis, ExecutorService executor, Duration maxWait) {
    this.jedis = Objects.requireNonNull(jedis, "jedis");
    this.executor = executor;
    this.maxWait = Objects.requireNonNull(maxWait, "maxWait");
  }

  /** Runs every call on {@code threads} daemon platform threads, bounded by {@code maxWait}. */
  public static JedisBudgetStore onPlatformThreads(
      UnifiedJedis jedis, int threads, Duration maxWait) {
    return onPlatformThreads(jedis, threads, threads, maxWait);
  }

  /**
   * Same, with the worker pool and its bounded work queue (C7) sized independently (V5): {@code
   * threads} need not equal the Jedis connection pool's own {@code max-total} — a small, contended
   * connection pool and a large burst of concurrent virtual-thread callers are two different
   * numbers, and workers simply block on the connection pool the way a virtual thread never should.
   */
  public static JedisBudgetStore onPlatformThreads(
      UnifiedJedis jedis, int threads, int queueSize, Duration maxWait) {
    int n = Math.max(1, threads);
    int q = Math.max(1, queueSize);
    var pool =
        new ThreadPoolExecutor(
            n,
            n,
            0L,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(q),
            r -> {
              var t = new Thread(r, "agentguard-redis");
              t.setDaemon(true);
              return t;
            },
            new ThreadPoolExecutor.AbortPolicy());
    return new JedisBudgetStore(jedis, pool, maxWait);
  }

  public boolean isOnPlatformThreads() {
    return executor != null;
  }

  /** Shuts the platform-thread pool down, if this store has one (C8). No-op otherwise. */
  @Override
  public void close() {
    if (executor != null) {
      executor.shutdownNow();
    }
  }

  @Override
  public long incrementAndGet(String key, long amount, Duration ttl) {
    return run(
        () -> {
          Object result =
              jedis.eval(
                  SCRIPT,
                  List.of(key),
                  List.of(Long.toString(amount), Long.toString(ttl.toMillis())));
          return ((Number) result).longValue();
        });
  }

  @Override
  public long current(String key) {
    return run(
        () -> {
          String v = jedis.get(key);
          return v == null ? 0L : Long.parseLong(v);
        });
  }

  private long run(Callable<Long> call) {
    if (executor == null) {
      try {
        return call.call();
      } catch (Exception e) {
        throw new AgentGuardException(ErrorCodes.GUARD_UNAVAILABLE, "Redis budget store failed", e);
      }
    }
    Future<Long> future;
    try {
      future = executor.submit(call);
    } catch (RejectedExecutionException e) {
      // the bounded queue is full: refuse immediately instead of piling work up (C7)
      throw new AgentGuardException(
          ErrorCodes.GUARD_UNAVAILABLE, "Redis budget store pool saturated", e);
    }
    try {
      return future.get(maxWait.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      // don't abandon it on the queue: cancel and remove it so the slot is free for the next call
      future.cancel(true);
      if (executor instanceof ThreadPoolExecutor tpe) {
        tpe.getQueue().remove(future);
      }
      throw new AgentGuardException(
          ErrorCodes.GUARD_UNAVAILABLE, "Redis budget store did not answer within " + maxWait, e);
    } catch (ExecutionException e) {
      throw new AgentGuardException(
          ErrorCodes.GUARD_UNAVAILABLE, "Redis budget store failed", e.getCause());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AgentGuardException(
          ErrorCodes.GUARD_UNAVAILABLE, "interrupted waiting for Redis", e);
    }
  }
}

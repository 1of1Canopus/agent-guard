package com.housedevinci.agentguard.adapter.redis;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import redis.clients.jedis.ConnectionPoolConfig;
import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.JedisPooled;

/**
 * Child-JVM body for {@code CipherProbeJedisPinningTest}: N virtual (or platform) threads hammer
 * {@link JedisBudgetStore} through a cold pool of {@code maxTotal} connections. Prints DONE or
 * HUNG.
 *
 * <p>args: host port maxTotal threads virtual(true|false) waitSeconds [minIdle] [prefill]
 */
public final class CipherProbeJedisPinningMain {
  private CipherProbeJedisPinningMain() {}

  public static void main(String[] args) throws Exception {
    String host = args[0];
    int port = Integer.parseInt(args[1]);
    int maxTotal = Integer.parseInt(args[2]);
    int threads = Integer.parseInt(args[3]);
    boolean virtual = Boolean.parseBoolean(args[4]);
    int waitSeconds = Integer.parseInt(args[5]);
    int minIdle = args.length > 6 ? Integer.parseInt(args[6]) : 0;
    boolean prefill = args.length > 7 && Boolean.parseBoolean(args[7]);

    var config = new ConnectionPoolConfig();
    config.setMaxTotal(maxTotal);
    config.setMaxIdle(maxTotal);
    config.setMinIdle(minIdle);
    var jedis = new JedisPooled(new HostAndPort(host, port), config);
    if (prefill) {
      // warm the pool from a platform thread before any virtual thread touches it
      jedis.getPool().preparePool();
    }
    var store = new JedisBudgetStore(jedis);
    var key = "cipher:pin:" + System.nanoTime();

    var start = new CountDownLatch(1);
    var done = new CountDownLatch(threads);
    List<Thread> list = new ArrayList<>();
    for (int i = 0; i < threads; i++) {
      Runnable body =
          () -> {
            try {
              start.await();
              for (int j = 0; j < 5; j++) {
                store.incrementAndGet(key, 1, Duration.ofMinutes(1));
              }
            } catch (Exception e) {
              System.out.println("ERR " + e);
            } finally {
              done.countDown();
            }
          };
      list.add(virtual ? Thread.ofVirtual().unstarted(body) : Thread.ofPlatform().unstarted(body));
    }
    list.forEach(Thread::start);
    long t0 = System.nanoTime();
    start.countDown();
    boolean finished = done.await(waitSeconds, TimeUnit.SECONDS);
    long ms = (System.nanoTime() - t0) / 1_000_000;
    System.out.println(
        (finished ? "DONE" : "HUNG")
            + " virtual="
            + virtual
            + " threads="
            + threads
            + " maxTotal="
            + maxTotal
            + " remaining="
            + done.getCount()
            + " ms="
            + ms
            + " count="
            + (finished ? store.current(key) : -1));
    System.out.flush();
    System.exit(finished ? 0 : 3);
  }
}

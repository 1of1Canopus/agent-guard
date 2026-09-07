package com.housedevinci.agentguard.adapter.redis;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Cipher probe for the "Jedis + virtual threads deadlock" note. Runs {@link
 * CipherProbeJedisPinningMain} in a child JVM so the virtual-thread scheduler can be sized and
 * {@code -Djdk.tracePinnedThreads=full} can report where a carrier is pinned.
 */
@Testcontainers
class CipherProbeJedisPinningTest {

  @Container
  static final GenericContainer<?> REDIS =
      new GenericContainer<>(
              "redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99")
          .withExposedPorts(6379);

  record Run(int exit, String out) {}

  private static Run run(int maxTotal, int threads, boolean virtual, int minIdle, boolean prefill)
      throws IOException, InterruptedException {
    var cmd = new ArrayList<String>();
    cmd.add(System.getProperty("java.home") + "/bin/java");
    cmd.add("-cp");
    cmd.add(System.getProperty("java.class.path"));
    cmd.add(CipherProbeJedisPinningMain.class.getName());
    cmd.add(REDIS.getHost());
    cmd.add(String.valueOf(REDIS.getMappedPort(6379)));
    cmd.add(String.valueOf(maxTotal));
    cmd.add(String.valueOf(threads));
    cmd.add(String.valueOf(virtual));
    cmd.add("10");
    cmd.add(String.valueOf(minIdle));
    cmd.add(String.valueOf(prefill));
    var p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
    var out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    if (!p.waitFor(60, TimeUnit.SECONDS)) {
      p.destroyForcibly();
    }
    System.out.println(
        "---- child jvm: "
            + out.lines()
                .filter(l -> l.startsWith("DONE") || l.startsWith("HUNG") || l.startsWith("ERR"))
                .findFirst()
                .orElse(out));
    return new Run(p.exitValue(), out);
  }

  @Test
  void probe_cold_pool_growth_under_virtual_threads_deadlocks_the_jvm_at_default_settings()
      throws Exception {
    // 64 concurrent budget checks against a cold pool of 4 connections, default scheduler
    // (parallelism = cores, maxPoolSize = 256): nothing ever completes. Thread dump: virtual
    // threads blocked on monitorenter in GenericObjectPool.create() (synchronized
    // makeObjectCountLock) pin every carrier while the threads inside makeObject() are parked on
    // the Jedis handshake read and can never remount.
    var virtual = run(4, 64, true, 0, false);
    assertThat(virtual.out()).contains("HUNG");
    assertThat(virtual.exit()).isEqualTo(3);

    var platform = run(4, 64, false, 0, false);
    assertThat(platform.out()).contains("DONE");
  }

  @Test
  void probe_mitigations_pool_at_least_concurrency_or_prefilled_pool_complete() throws Exception {
    assertThat(run(64, 64, true, 0, false).out()).contains("DONE");
    assertThat(run(8, 200, true, 8, true).out()).contains("DONE");
  }
}

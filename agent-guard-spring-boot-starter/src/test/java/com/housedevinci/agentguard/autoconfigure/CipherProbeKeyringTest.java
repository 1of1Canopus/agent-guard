package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.ai.AgentGuardSpringAiAutoConfiguration;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.mcp.AgentGuardMcpAutoConfiguration;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/** Cipher verification pass on 722e9a5: keyring / opt-out configuration attacks. */
@org.junit.jupiter.api.extension.ExtendWith(
    org.springframework.boot.test.system.OutputCaptureExtension.class)
class CipherProbeKeyringTest {

  private static final String S1 = "A".repeat(32);
  private static final String S2 = "B".repeat(32);

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  AgentGuardAutoConfiguration.class,
                  AgentGuardSpringAiAutoConfiguration.class,
                  AgentGuardMcpAutoConfiguration.class))
          .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY");

  @SuppressWarnings("unchecked")
  private static Map<String, byte[]> keyring(
      org.springframework.boot.test.context.assertj.AssertableApplicationContext ctx) {
    return (Map<String, byte[]>) ctx.getBean("auditKeyring");
  }

  /**
   * H1. A retired-key entry that reuses the appending key's id with a different secret silently
   * replaces the appending key in the verifier's keyring: every row this instance writes then fails
   * to verify. The properties javadoc calls the same id "redundant, not an error"; it is only
   * redundant when the secret is identical, which nothing checks.
   */
  @Test
  void probe_a_retired_key_entry_can_shadow_the_appending_key() {
    runner
        .withPropertyValues(
            "agentguard.audit.hmac-secret=" + S1,
            "agentguard.audit.hmac-key-id=k1",
            "agentguard.audit.hmac-keys.k1=" + S2)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(keyring(ctx).get("k1")).isEqualTo(S2.getBytes(StandardCharsets.UTF_8));
              // i.e. NOT the secret the sink is appending with
              assertThat(keyring(ctx).get("k1"))
                  .isNotEqualTo(
                      ctx.getBean(AuditChain.class) != null
                          ? S1.getBytes(StandardCharsets.UTF_8)
                          : null);
            });
  }

  /**
   * H2. {@code agentguard.audit.unkeyed=true} together with a real {@code hmac-secret} is a
   * contradiction. The secret wins (the safe direction) but nothing says so: no WARN, no failure,
   * and the operator who believes they are running unkeyed gets a keyed trail (or, on an existing
   * unkeyed trail, an AG-AUDIT-001 refusal they did not ask for).
   */
  @Test
  void probe_unkeyed_true_with_a_secret_is_silently_ignored(
      org.springframework.boot.test.system.CapturedOutput output) {
    runner
        .withPropertyValues("agentguard.audit.unkeyed=true", "agentguard.audit.hmac-secret=" + S1)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(AuditChain.class).isKeyed()).isTrue();
              assertThat(output).doesNotContain("unkeyed");
            });
  }

  /** H3. A short secret in the retired keyring is refused, naming the id. */
  @Test
  void confirms_a_short_retired_key_is_refused() {
    runner
        .withPropertyValues(
            "agentguard.audit.hmac-secret=" + S1, "agentguard.audit.hmac-keys.k0=tooshort")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .hasMessageContaining("agentguard.audit.hmac-keys.k0")
                  .hasMessageContaining("at least 32 bytes");
              assertThat(ctx.getStartupFailure()).rootCause().hasMessageNotContaining("tooshort");
            });
  }

  /** H4. The reserved id {@code none} is refused, in both the appending id and the ring. */
  @Test
  void confirms_the_reserved_none_id_is_refused() {
    runner
        .withPropertyValues(
            "agentguard.audit.hmac-secret=" + S1, "agentguard.audit.hmac-key-id=none")
        .run(ctx -> assertThat(ctx).hasFailed());
    runner
        .withPropertyValues(
            "agentguard.audit.hmac-secret=" + S1, "agentguard.audit.hmac-keys.none=" + S2)
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  /** H5. A blank appending key id is refused rather than silently used. */
  @Test
  void confirms_a_blank_key_id_is_refused() {
    runner
        .withPropertyValues("agentguard.audit.hmac-secret=" + S1, "agentguard.audit.hmac-key-id=  ")
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  /** H6. No startup failure message anywhere carries the secret bytes. */
  @Test
  void confirms_no_startup_message_carries_the_secret(
      org.springframework.boot.test.system.CapturedOutput output) {
    String secret = "PLAINTEXT-SECRET-VALUE-DO-NOT-LOG-0123456789";
    runner
        .withPropertyValues(
            "agentguard.audit.hmac-secret=" + secret, "agentguard.audit.hmac-keys.k0=short")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure().toString()).doesNotContain("PLAINTEXT-SECRET");
              assertThat(output).doesNotContain("PLAINTEXT-SECRET");
            });
  }
}

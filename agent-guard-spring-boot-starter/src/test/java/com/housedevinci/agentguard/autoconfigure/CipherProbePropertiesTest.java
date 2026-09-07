package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.domain.Principal;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

/** Cipher probes for property validation, flipped (L7). */
@ExtendWith(OutputCaptureExtension.class)
class CipherProbePropertiesTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
          .withPropertyValues(
              "agentguard.enabled=true",
              "agentguard.audit.unkeyed=true",
              "agentguard.store=MEMORY");

  private static String messages(Throwable t) {
    var sb = new StringBuilder();
    while (t != null) {
      sb.append(t.getMessage()).append(' ');
      t = t.getCause();
    }
    return sb.toString();
  }

  @Test
  void non_positive_durations_fail_naming_the_property() {
    runner
        .withPropertyValues("agentguard.approval.ttl=PT0S")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(messages(ctx.getStartupFailure()))
                  .contains("agentguard.approval.ttl must be positive");
            });
    runner
        .withPropertyValues(
            "agentguard.budgets.limits[0].scope=PRINCIPAL",
                "agentguard.budgets.limits[0].kind=TOOL_CALLS",
            "agentguard.budgets.limits[0].window=PT0S", "agentguard.budgets.limits[0].limit=3")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(messages(ctx.getStartupFailure()))
                  .contains("agentguard.budgets.limits[].window must be positive");
            });
    runner
        .withPropertyValues("agentguard.approval.notifier.webhook-timeout=PT0S")
        .run(
            ctx ->
                assertThat(messages(ctx.getStartupFailure()))
                    .contains("agentguard.approval.notifier.webhook-timeout"));
    runner
        .withPropertyValues("agentguard.redis.pool.max-wait=PT0S")
        .run(
            ctx ->
                assertThat(messages(ctx.getStartupFailure()))
                    .contains("agentguard.redis.pool.max-wait"));
  }

  @Test
  void empty_approval_set_and_empty_sensitive_keys_warn_at_startup(CapturedOutput output) {
    runner
        .withPropertyValues(
            "agentguard.policy.approval-required-for=", "agentguard.redaction.sensitive-keys=")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(output)
                  .contains("agentguard.policy.approval-required-for is empty")
                  .contains("agentguard.redaction.sensitive-keys is empty");
            });
  }

  @Test
  void what_is_fine() {
    runner
        .withPropertyValues("agentguard.store=JDBC")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(messages(ctx.getStartupFailure()))
                  .contains("agentguard.store=JDBC requires a DataSource bean");
            });
    runner
        .withPropertyValues("agentguard.budgets.store=REDIS")
        .run(ctx -> assertThat(messages(ctx.getStartupFailure())).contains("agentguard.redis.uri"));
    runner
        .withPropertyValues("agentguard.redaction.max-preview-length=3")
        .run(ctx -> assertThat(ctx).hasFailed());
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();
          var r =
              ctx.getBean(ToolGuard.class)
                  .execute(
                      ToolInvocation.of(
                          new Principal("u", Set.of("ADMIN"), Set.of(), null), "unknown", "{}"),
                      Optional.empty(),
                      a -> "ran");
          assertThat(r.toModelText()).contains("AG-POLICY-004");
        });
  }
}

package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.domain.ArgumentRedactor;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/** Cipher probes for property validation and fail-closed defaults of the starter. */
class CipherProbePropertiesTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
          .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY");

  private static String rootMessage(Throwable t) {
    while (t.getCause() != null) {
      t = t.getCause();
    }
    return t.getMessage();
  }

  @Test
  void probe_non_positive_durations_fail_without_naming_the_property() {
    runner
        .withPropertyValues("agentguard.approval.ttl=PT0S")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              var msg = rootMessage(ctx.getStartupFailure());
              System.out.println("ttl=PT0S -> " + msg);
              assertThat(msg).doesNotContain("agentguard.approval.ttl");
            });
    runner
        .withPropertyValues(
            "agentguard.budgets.limits[0].scope=PRINCIPAL",
            "agentguard.budgets.limits[0].kind=TOOL_CALLS",
            "agentguard.budgets.limits[0].window=PT0S",
            "agentguard.budgets.limits[0].limit=3")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              var msg = rootMessage(ctx.getStartupFailure());
              System.out.println("window=PT0S -> " + msg);
              assertThat(msg).doesNotContain("agentguard.budgets");
            });
  }

  @Test
  void probe_empty_approval_set_and_empty_sensitive_keys_are_accepted_silently() {
    runner
        .withPropertyValues(
            "agentguard.policy.approval-required-for=", "agentguard.redaction.sensitive-keys=")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              ctx.getBean(ToolPolicyRegistry.class)
                  .register("wipe", PolicyRule.unrestricted(SideEffect.DESTRUCTIVE));
              var r =
                  ctx.getBean(ToolGuard.class)
                      .execute(
                          ToolInvocation.of(Principal.anonymous(), "wipe", "{}"),
                          Optional.empty(),
                          a -> "wiped");
              // DESTRUCTIVE, anonymous, executed straight away: configuration allowed it
              assertThat(r.toModelText()).isEqualTo("wiped");
              assertThat(ctx.getBean(ArgumentRedactor.class).preview("{\"password\":\"hunter2\"}"))
                  .contains("hunter2");
            });
  }

  @Test
  void probe_what_is_fine() {
    runner
        .withPropertyValues("agentguard.store=JDBC")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(rootMessage(ctx.getStartupFailure()))
                  .contains("agentguard.store=JDBC requires a DataSource bean");
            });
    runner
        .withPropertyValues("agentguard.budgets.store=REDIS")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(rootMessage(ctx.getStartupFailure())).contains("agentguard.redis.uri");
            });
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

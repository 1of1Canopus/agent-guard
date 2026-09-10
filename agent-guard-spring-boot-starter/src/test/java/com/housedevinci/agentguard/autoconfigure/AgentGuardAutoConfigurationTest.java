package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.ai.AgentGuard;
import com.housedevinci.agentguard.ai.AgentGuardSpringAiAutoConfiguration;
import com.housedevinci.agentguard.application.BudgetEnforcer;
import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.domain.BudgetKind;
import com.housedevinci.agentguard.domain.BudgetScope;
import com.housedevinci.agentguard.mcp.AgentGuardMcpAutoConfiguration;
import com.housedevinci.agentguard.mcp.McpToolGuard;
import com.housedevinci.agentguard.security.ToolPolicyAuthorizationManager;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

@org.junit.jupiter.api.extension.ExtendWith(
    org.springframework.boot.test.system.OutputCaptureExtension.class)
class AgentGuardAutoConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  AgentGuardAutoConfiguration.class,
                  AgentGuardSpringAiAutoConfiguration.class,
                  AgentGuardMcpAutoConfiguration.class));

  @Test
  void off_by_default() {
    runner.run(
        ctx -> assertThat(ctx).doesNotHaveBean(ToolGuard.class).doesNotHaveBean(AgentGuard.class));
  }

  @Test
  void memory_store_wires_everything() {
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.budgets.limits[0].scope=PRINCIPAL",
            "agentguard.budgets.limits[0].kind=TOOL_CALLS",
            "agentguard.budgets.limits[0].window=PT1M",
            "agentguard.budgets.limits[0].limit=3")
        .run(
            ctx -> {
              assertThat(ctx)
                  .hasSingleBean(ToolGuard.class)
                  .hasSingleBean(AgentGuard.class)
                  .hasSingleBean(McpToolGuard.class)
                  .hasSingleBean(ToolPolicyAuthorizationManager.class);
              assertThat(ctx.getBean(com.housedevinci.agentguard.domain.AuditSink.class))
                  .isInstanceOf(InMemoryAuditSink.class);
              var limits = ctx.getBean(BudgetEnforcer.class).limits();
              assertThat(limits).hasSize(1);
              assertThat(limits.get(0).scope()).isEqualTo(BudgetScope.PRINCIPAL);
              assertThat(limits.get(0).kind()).isEqualTo(BudgetKind.TOOL_CALLS);
              assertThat(limits.get(0).limit()).isEqualTo(3);
            });
  }

  @Test
  void jdbc_store_without_datasource_fails_fast_naming_the_property() {
    runner
        .withPropertyValues("agentguard.enabled=true", "agentguard.audit.unkeyed=true")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .hasMessageContaining("no DataSource found")
                  .hasMessageContaining("agentguard.store=memory")
                  .hasMessageContaining("not for production");
            });
  }

  @Test
  void redis_budgets_without_uri_fail_fast() {
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.budgets.store=REDIS")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .hasMessageContaining("agentguard.redis.uri is required");
            });
  }

  @Test
  void invalid_limit_is_rejected_by_validation() {
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.budgets.limits[0].limit=0")
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void jedis_pool_is_prefilled_by_default_and_sized_from_properties() {
    var pool = new AgentGuardProperties.Pool();
    pool.setMaxTotal(32);
    var config = JedisBudgetStoreFactory.poolConfig(pool);
    assertThat(config.getMaxTotal()).isEqualTo(32);
    assertThat(config.getMinIdle()).isEqualTo(32);
    assertThat(config.getMaxIdle()).isEqualTo(32);
    assertThat(config.getMaxWaitDuration()).isEqualTo(java.time.Duration.ofSeconds(2));
    assertThat(pool.isPreparePool()).isTrue();
    pool.setMinIdle(4);
    assertThat(JedisBudgetStoreFactory.poolConfig(pool).getMinIdle()).isEqualTo(4);
  }

  @Test
  void tenant_limit_without_tenant_resolver_starts_with_a_warning_and_denies_by_default() {
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.budgets.limits[0].scope=TENANT",
            "agentguard.budgets.limits[0].limit=3")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(BudgetEnforcer.class).missingSubjectPolicy())
                  .isEqualTo(com.housedevinci.agentguard.application.MissingSubjectPolicy.DENY);
            });
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.strict=false")
        .run(
            ctx ->
                assertThat(ctx.getBean(BudgetEnforcer.class).missingSubjectPolicy())
                    .isEqualTo(com.housedevinci.agentguard.application.MissingSubjectPolicy.SKIP));
  }

  @Test
  void limit_kind_and_scope_combinations_are_validated() {
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.budgets.limits[0].scope=PRINCIPAL",
            "agentguard.budgets.limits[0].kind=STEPS")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .hasMessageContaining("agentguard.budgets.limits[0]")
                  .hasMessageContaining("STEPS");
            });
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.budgets.limits[0].scope=CONVERSATION",
            "agentguard.budgets.limits[0].kind=TOOL_CALLS")
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void conversation_limit_without_principal_limit_warns(
      org.springframework.boot.test.system.CapturedOutput output) {
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.budgets.limits[0].scope=CONVERSATION",
            "agentguard.budgets.limits[0].kind=STEPS")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(output).contains("CONVERSATION limit but no PRINCIPAL limit");
            });
  }

  /**
   * Design change ("keyed-from-birth"): {@code agentguard.audit.hmac-secret} is required by
   * default. Missing, and without the explicit {@code agentguard.audit.unkeyed=true} opt-out,
   * startup fails naming the property and the remedy (generate a secret with {@code openssl rand
   * -base64 32}).
   */
  @Test
  void missing_hmac_secret_fails_startup_naming_the_property_and_the_remedy() {
    runner
        .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .hasMessageContaining("agentguard.audit.hmac-secret")
                  .hasMessageContaining("agentguard.audit.unkeyed")
                  .hasMessageContaining("openssl rand -base64 32");
            });
  }

  /**
   * The explicit local-dev opt-out: {@code agentguard.audit.unkeyed=true} starts (the trail is not
   * protected against a database writer rewriting it) but warns at every startup, not just the
   * first, so the trade-off cannot go unnoticed after the person who set it has moved on.
   */
  @Test
  void unkeyed_opt_out_starts_but_warns_every_time(
      org.springframework.boot.test.system.CapturedOutput output) {
    runner
        .withPropertyValues(
            "agentguard.enabled=true", "agentguard.store=MEMORY", "agentguard.audit.unkeyed=true")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(com.housedevinci.agentguard.domain.AuditChain.class).isKeyed())
                  .isFalse();
              assertThat(output)
                  .contains("audit trail is unkeyed")
                  .contains("a database writer can rewrite it undetected");
            });
    runner
        .withPropertyValues(
            "agentguard.enabled=true", "agentguard.store=MEMORY", "agentguard.audit.unkeyed=true")
        .run(
            ctx ->
                assertThat(output.getAll().split("audit trail is unkeyed", -1).length - 1)
                    .isGreaterThanOrEqualTo(2));
  }

  @Test
  void hmac_secret_must_be_long_enough_and_keys_the_chain() {
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.store=MEMORY",
            "agentguard.audit.hmac-secret=short")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .hasMessageContaining("agentguard.audit.hmac-secret");
            });
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.store=MEMORY",
            "agentguard.audit.hmac-secret=0123456789abcdef0123456789abcdef")
        .run(
            ctx ->
                assertThat(
                        ctx.getBean(com.housedevinci.agentguard.domain.AuditChain.class).isKeyed())
                    .isTrue());
  }

  @Test
  void insecure_webhook_url_fails_startup_unless_allowed() {
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.approval.notifier.webhook-url=http://hooks.example.com/x")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              var sb = new StringBuilder();
              for (Throwable t = ctx.getStartupFailure(); t != null; t = t.getCause()) {
                sb.append(t.getMessage()).append(' ');
              }
              assertThat(sb.toString()).contains("webhook-allow-insecure");
            });
    runner
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.audit.unkeyed=true",
            "agentguard.store=MEMORY",
            "agentguard.approval.notifier.webhook-url=http://hooks.example.com/x",
            "agentguard.approval.notifier.webhook-allow-insecure=true")
        .run(ctx -> assertThat(ctx).hasNotFailed());
  }
}

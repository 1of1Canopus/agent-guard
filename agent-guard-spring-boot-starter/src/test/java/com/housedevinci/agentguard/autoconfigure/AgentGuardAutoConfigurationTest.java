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
        .withPropertyValues("agentguard.enabled=true")
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
            "agentguard.enabled=true", "agentguard.store=MEMORY", "agentguard.budgets.store=REDIS")
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
            "agentguard.enabled=true", "agentguard.store=MEMORY", "agentguard.strict=false")
        .run(
            ctx ->
                assertThat(ctx.getBean(BudgetEnforcer.class).missingSubjectPolicy())
                    .isEqualTo(com.housedevinci.agentguard.application.MissingSubjectPolicy.SKIP));
  }
}

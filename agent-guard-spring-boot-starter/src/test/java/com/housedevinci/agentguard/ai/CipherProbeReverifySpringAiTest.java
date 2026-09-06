package com.housedevinci.agentguard.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.security.PrincipalResolver;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.ToolResponseMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.DefaultToolCallingManager;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.support.ToolCallbacks;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/** Cipher re-verification probes for the ToolCallingManager chokepoint and the run-as resume. */
class CipherProbeReverifySpringAiTest {

  static final AtomicInteger REFUNDS = new AtomicInteger();
  static volatile PrincipalResolver RESOLVER;

  static class OrderTools {
    @Tool(description = "Refund an order")
    @ToolPolicy(roles = "SUPPORT", sideEffect = SideEffect.DESTRUCTIVE)
    public String refundOrder(String orderId) {
      REFUNDS.incrementAndGet();
      // what a nested guarded call (or Tenantify / @PreAuthorize) would see while resumed
      var p = RESOLVER.resolve();
      return "refunded "
          + orderId
          + " as "
          + p.id()
          + " roles="
          + p.roles()
          + " tenant="
          + p.tenantId().orElse("none");
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class ToolsConfig {
    @Bean
    OrderTools orderTools() {
      return new OrderTools();
    }
  }

  /** Mimics Spring AI's ToolCallingAutoConfiguration, registered before Agent Guard's config. */
  @Configuration(proxyBeanMethods = false)
  static class SpringAiLikeConfig {
    @Bean
    @ConditionalOnMissingBean
    ToolCallingManager toolCallingManager() {
      return DefaultToolCallingManager.builder().build();
    }
  }

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  AgentGuardAutoConfiguration.class, AgentGuardSpringAiAutoConfiguration.class))
          .withUserConfiguration(ToolsConfig.class)
          .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY");

  @AfterEach
  void clearSecurity() {
    SecurityContextHolder.clearContext();
  }

  private static void loginAs(String user, String... roles) {
    var auth =
        new TestingAuthenticationToken(
            user,
            "n/a",
            List.of(roles).stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r)).toList());
    auth.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(auth);
  }

  private static String runToolCall(
      ToolCallingManager manager, ToolCallback[] callbacks, String tool, String argsJson) {
    var options =
        ToolCallingChatOptions.builder().toolCallbacks(callbacks).toolContext(Map.of()).build();
    var prompt = new Prompt(new UserMessage("do it"), options);
    var assistant =
        AssistantMessage.builder()
            .content("")
            .toolCalls(List.of(new AssistantMessage.ToolCall("call-1", "function", tool, argsJson)))
            .build();
    var result =
        manager.executeToolCalls(prompt, new ChatResponse(List.of(new Generation(assistant))));
    var last =
        (ToolResponseMessage)
            result.conversationHistory().get(result.conversationHistory().size() - 1);
    return last.getResponses().get(0).responseData();
  }

  @Test
  void spring_ai_registering_its_manager_first_still_yields_one_guarded_bean() {
    runner
        .withUserConfiguration(SpringAiLikeConfig.class)
        .run(
            ctx -> {
              REFUNDS.set(0);
              assertThat(ctx.getBeansOfType(ToolCallingManager.class)).hasSize(1);
              var manager = ctx.getBean(ToolCallingManager.class);
              assertThat(manager).isInstanceOf(GuardedToolCallingManager.class);
              assertThat(((GuardedToolCallingManager) manager).delegate())
                  .isInstanceOf(DefaultToolCallingManager.class);
              loginAs("eve", "VIEWER");
              var out =
                  runToolCall(
                      manager,
                      ToolCallbacks.from(new OrderTools()),
                      "refundOrder",
                      "{\"orderId\":\"1\"}");
              assertThat(out).contains("AG-POLICY-001");
              assertThat(REFUNDS).hasValue(0);
            });
  }

  /** R3, documented: a manager built by hand never reaches the bean post-processor. */
  @Test
  void hand_built_manager_outside_the_context_is_documented_as_unguarded() {
    runner.run(
        ctx -> {
          REFUNDS.set(0);
          RESOLVER = ctx.getBean(PrincipalResolver.class);
          loginAs("eve", "VIEWER");
          var out =
              runToolCall(
                  DefaultToolCallingManager.builder().build(),
                  ToolCallbacks.from(new OrderTools()),
                  "refundOrder",
                  "{\"orderId\":\"1\"}");
          assertThat(out).contains("refunded 1");
          assertThat(REFUNDS).hasValue(1);
        });
  }

  /** A host TenantResolver that only knows its own tokens (as real ones do). */
  @Configuration(proxyBeanMethods = false)
  static class TenantConfig {
    @Bean
    com.housedevinci.agentguard.security.TenantResolver tenantResolver() {
      return auth ->
          auth instanceof TestingAuthenticationToken && "bob".equals(auth.getName())
              ? java.util.Optional.of("acme")
              : java.util.Optional.empty();
    }
  }

  @Test // R5 flipped: the nested principal during a resumed call keeps roles, scopes and tenant
  void nested_principal_during_resume_keeps_roles_and_tenant() throws Exception {
    runner
        .withUserConfiguration(TenantConfig.class)
        .run(
            ctx -> {
              REFUNDS.set(0);
              RESOLVER = ctx.getBean(PrincipalResolver.class);
              var manager = ctx.getBean(ToolCallingManager.class);
              loginAs("bob", "SUPPORT");
              assertThat(
                      runToolCall(
                          manager,
                          ToolCallbacks.from(new OrderTools()),
                          "refundOrder",
                          "{\"orderId\":\"7\"}"))
                  .contains("AWAITING_APPROVAL");
              var approvals = ctx.getBean(ApprovalService.class);
              var d = approvals.pending(10).get(0);
              assertThat(d.principal().tenantId()).contains("acme");
              loginAs("alice", "APPROVER");
              var outcome = approvals.approve(d.id(), "alice", d.argsHash());
              assertThat(outcome.result().toModelText())
                  .contains("as bob")
                  .contains("roles=[SUPPORT]")
                  .contains("tenant=acme");
              assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
                  .isEqualTo("alice");
            });
    // the default resolver understands the run-as token as well
    var now = java.time.Instant.parse("2026-09-06T10:00:00Z");
    var decision =
        com.housedevinci.agentguard.domain.PendingDecision.park(
            new com.housedevinci.agentguard.domain.Principal(
                "bob", java.util.Set.of("SUPPORT"), java.util.Set.of(), "acme"),
            new com.housedevinci.agentguard.domain.ToolRef("t", SideEffect.WRITE),
            "{}",
            "{}",
            null,
            "c",
            now,
            now.plusSeconds(60));
    var runAs =
        new com.housedevinci.agentguard.security.SecurityContextResumeContextProvider()
            .runAs(decision, () -> SecurityContextHolder.getContext().getAuthentication());
    assertThat(new com.housedevinci.agentguard.security.NoTenantResolver().tenantOf(runAs))
        .contains("acme");
  }

  /** Mimics Spring AI's ToolCallingAutoConfiguration with spring.ai.tools.limits.* applied. */
  @Configuration(proxyBeanMethods = false)
  static class LimitedManagerConfig {
    @Bean
    @ConditionalOnMissingBean
    ToolCallingManager toolCallingManager() {
      return DefaultToolCallingManager.builder()
          .maxTotalToolCalls(1)
          .onLimitExceeded(
              org.springframework.ai.model.tool.ToolCallLimitBehavior.RETURN_ERROR_RESPONSE)
          .build();
    }
  }

  @Test // R1 flipped: Spring AI's own manager (with its limits) is the one that gets wrapped
  void spring_ai_tool_call_limits_survive_the_guard() {
    runner
        .withUserConfiguration(LimitedManagerConfig.class)
        .run(
            ctx -> {
              REFUNDS.set(0);
              var manager = ctx.getBean(ToolCallingManager.class);
              assertThat(manager).isInstanceOf(GuardedToolCallingManager.class);
              assertThat(((GuardedToolCallingManager) manager).delegate())
                  .isInstanceOf(DefaultToolCallingManager.class);
              assertThat(ctx.getBeansOfType(ToolCallingManager.class)).hasSize(1);
              loginAs("bob", "SUPPORT");
              var callbacks = ToolCallbacks.from(new OrderTools());
              var options =
                  ToolCallingChatOptions.builder()
                      .toolCallbacks(callbacks)
                      .toolContext(Map.of())
                      .build();
              var prompt = new Prompt(new UserMessage("do it twice"), options);
              var assistant =
                  AssistantMessage.builder()
                      .content("")
                      .toolCalls(
                          List.of(
                              new AssistantMessage.ToolCall(
                                  "c1", "function", "refundOrder", "{\"orderId\":\"1\"}"),
                              new AssistantMessage.ToolCall(
                                  "c2", "function", "refundOrder", "{\"orderId\":\"2\"}")))
                      .build();
              var result =
                  manager.executeToolCalls(
                      prompt, new ChatResponse(List.of(new Generation(assistant))));
              var last =
                  (ToolResponseMessage)
                      result.conversationHistory().get(result.conversationHistory().size() - 1);
              var texts = last.getResponses().stream().map(r -> r.responseData()).toList();
              // first call went through the guard (parked), the second hit Spring AI's own limit
              assertThat(texts.get(0)).contains("AWAITING_APPROVAL");
              assertThat(String.join(" ", texts)).containsIgnoringCase("limit");
              assertThat(REFUNDS).hasValue(0);
            });
  }
}

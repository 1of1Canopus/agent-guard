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

  @Test
  void probe_hand_built_manager_outside_the_context_bypasses_the_chokepoint() {
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

  @Test
  void probe_nested_principal_during_resume_keeps_roles_but_loses_the_tenant() {
    runner.run(
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
          loginAs("alice", "APPROVER");
          var outcome = approvals.approve(d.id(), "alice", d.argsHash());
          assertThat(outcome.result().toModelText())
              .contains("as bob")
              .contains("roles=[SUPPORT]")
              .contains("tenant=none");
          assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
              .isEqualTo("alice");
        });
  }
}

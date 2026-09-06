package com.housedevinci.agentguard.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.SideEffect;
import java.util.List;
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
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Drives the Spring AI tool-calling path the way a ChatModel does: a fake model answers with a tool
 * call and {@link DefaultToolCallingManager} executes it through the guarded callbacks.
 */
class GuardedToolCallbackTest {

  static final AtomicInteger REFUNDS = new AtomicInteger();

  static class OrderTools {
    @Tool(description = "Look up an order")
    @ToolPolicy(roles = "SUPPORT")
    public String lookupOrder(String orderId) {
      return "order " + orderId + " is shipped";
    }

    @Tool(description = "Refund an order")
    @ToolPolicy(roles = "SUPPORT", sideEffect = SideEffect.WRITE)
    public String refundOrder(String orderId, String password) {
      REFUNDS.incrementAndGet();
      return "refunded " + orderId;
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class ToolsConfig {
    @Bean
    OrderTools orderTools() {
      return new OrderTools();
    }

    @Bean
    ToolCallbackProvider orderToolCallbacks(OrderTools tools) {
      return MethodToolCallbackProvider.builder().toolObjects(tools).build();
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

  /**
   * What a ChatModel does after the LLM asked for a tool: run it through the ToolCallingManager.
   */
  private static String runToolCall(ToolCallback[] callbacks, String tool, String argsJson) {
    var options = ToolCallingChatOptions.builder().toolCallbacks(callbacks).build();
    var prompt = new Prompt(new UserMessage("do it"), options);
    var assistant =
        AssistantMessage.builder()
            .content("")
            .toolCalls(List.of(new AssistantMessage.ToolCall("call-1", "function", tool, argsJson)))
            .build();
    var response = new ChatResponse(List.of(new Generation(assistant)));
    var result = DefaultToolCallingManager.builder().build().executeToolCalls(prompt, response);
    var last =
        (ToolResponseMessage)
            result.conversationHistory().get(result.conversationHistory().size() - 1);
    return last.getResponses().get(0).responseData();
  }

  @Test
  void provider_beans_are_wrapped_and_policy_is_enforced_per_call() {
    runner.run(
        ctx -> {
          var provider = ctx.getBean(ToolCallbackProvider.class);
          assertThat(provider).isInstanceOf(AgentGuard.GuardedToolCallbackProvider.class);
          var callbacks = provider.getToolCallbacks();
          assertThat(callbacks).allMatch(c -> c instanceof GuardedToolCallback);

          loginAs("bob", "SUPPORT");
          assertThat(runToolCall(callbacks, "lookupOrder", "{\"orderId\":\"42\"}"))
              .isEqualTo("\"order 42 is shipped\"");

          loginAs("eve", "VIEWER");
          assertThat(runToolCall(callbacks, "lookupOrder", "{\"orderId\":\"42\"}"))
              .contains("\"error\":\"TOOL_DENIED\"")
              .contains("AG-POLICY-001");

          SecurityContextHolder.clearContext();
          assertThat(runToolCall(callbacks, "lookupOrder", "{\"orderId\":\"42\"}"))
              .contains("TOOL_DENIED");
        });
  }

  @Test
  void write_tool_is_parked_then_approval_executes_once() {
    runner.run(
        ctx -> {
          REFUNDS.set(0);
          var callbacks = ctx.getBean(ToolCallbackProvider.class).getToolCallbacks();
          loginAs("bob", "SUPPORT");
          var parked =
              runToolCall(
                  callbacks, "refundOrder", "{\"orderId\":\"42\",\"password\":\"hunter2\"}");
          assertThat(parked).contains("AWAITING_APPROVAL");
          assertThat(REFUNDS).hasValue(0);

          var approvals = ctx.getBean(ApprovalService.class);
          var pending = approvals.pending(10);
          assertThat(pending).hasSize(1);
          assertThat(pending.get(0).argsPreview())
              .contains("\"password\":\"***\"")
              .doesNotContain("hunter2");

          var outcome = approvals.approve(pending.get(0).id(), "alice");
          assertThat(outcome.result().toModelText()).isEqualTo("\"refunded 42\"");
          assertThat(REFUNDS).hasValue(1);
          approvals.approve(pending.get(0).id(), "alice");
          assertThat(REFUNDS).hasValue(1);
          assertThat(
                  approvals
                      .find(DecisionId.of(pending.get(0).id().toString()))
                      .orElseThrow()
                      .state())
              .isEqualTo(DecisionState.APPROVED);

          // the agent re-asks with the same arguments and gets the stored result, no second refund
          assertThat(
                  runToolCall(
                      callbacks, "refundOrder", "{\"orderId\":\"42\",\"password\":\"hunter2\"}"))
              .isEqualTo("\"refunded 42\"");
          assertThat(REFUNDS).hasValue(1);

          var audit = ctx.getBean(AuditReader.class).latest(10);
          assertThat(audit).extracting(e -> e.decision().name()).contains("PENDING", "APPROVED");
          assertThat(audit).allMatch(e -> e.hash() != null && e.hash().length() == 64);
        });
  }

  @Test
  void programmatic_guard_is_idempotent() {
    runner.run(
        ctx -> {
          var agentGuard = ctx.getBean(AgentGuard.class);
          var raw =
              MethodToolCallbackProvider.builder()
                  .toolObjects(new OrderTools())
                  .build()
                  .getToolCallbacks()[0];
          var guarded = agentGuard.guard(raw);
          assertThat(guarded).isInstanceOf(GuardedToolCallback.class);
          assertThat(agentGuard.guard(guarded)).isSameAs(guarded);
          assertThat(guarded.getToolDefinition().name()).isEqualTo(raw.getToolDefinition().name());
        });
  }
}

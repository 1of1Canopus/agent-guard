package com.housedevinci.agentguard.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
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
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.support.ToolCallbacks;
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

/** Cipher probes for the Spring AI integration seam, flipped: H1, H2 and M6 are fixed. */
class CipherProbeSpringAiTest {

  static final AtomicInteger REFUNDS = new AtomicInteger();

  static class OrderTools {
    @Tool(description = "Refund an order")
    @ToolPolicy(roles = "SUPPORT", sideEffect = SideEffect.DESTRUCTIVE)
    public String refundOrder(String orderId, ToolContext ctx) {
      REFUNDS.incrementAndGet();
      var auth = SecurityContextHolder.getContext().getAuthentication();
      return "refunded "
          + orderId
          + " tenant="
          + ctx.getContext().get("tenantId")
          + " runAs="
          + (auth == null ? "none" : auth.getName());
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

  /** An audit sink whose backing store is down. */
  static final class BrokenAudit implements AuditSink, AuditReader {
    @Override
    public AuditEvent append(AuditEvent event) {
      throw new IllegalStateException(
          "Agent Guard JDBC failure: Connection to db.internal:5432 refused (user agentguard)");
    }

    @Override
    public List<AuditEvent> readAfter(long afterSequence, int limit) {
      return List.of();
    }

    @Override
    public List<AuditEvent> latest(String tenantId, int limit) {
      return List.of();
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class BrokenAuditConfig {
    @Bean
    BrokenAudit brokenAudit() {
      return new BrokenAudit();
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
   * What a ChatModel does after the LLM asked for a tool: run it through the ToolCallingManager
   * bean.
   */
  private static String runToolCall(
      ToolCallingManager manager,
      ToolCallback[] callbacks,
      String tool,
      String argsJson,
      Map<String, Object> toolContext) {
    var options =
        ToolCallingChatOptions.builder().toolCallbacks(callbacks).toolContext(toolContext).build();
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

  @Test // H2 flipped: the ToolCallingManager chokepoint guards inline tools too
  void inline_tool_objects_are_guarded_through_the_tool_calling_manager() {
    runner.run(
        ctx -> {
          REFUNDS.set(0);
          assertThat(ctx.getBean(ToolPolicyRegistry.class).find("refundOrder")).isPresent();
          var manager = ctx.getBean(ToolCallingManager.class);
          assertThat(manager).isInstanceOf(GuardedToolCallingManager.class);
          ToolCallback[] inline = ToolCallbacks.from(new OrderTools());
          assertThat(inline).noneMatch(c -> c instanceof GuardedToolCallback);

          loginAs("eve", "VIEWER");
          var out =
              runToolCall(
                  manager, inline, "refundOrder", "{\"orderId\":\"42\"}", Map.of("tenantId", "x"));
          assertThat(out).contains("TOOL_DENIED").contains("AG-POLICY-001");
          assertThat(REFUNDS).hasValue(0);

          loginAs("bob", "SUPPORT");
          var parked =
              runToolCall(
                  manager, inline, "refundOrder", "{\"orderId\":\"42\"}", Map.of("tenantId", "x"));
          assertThat(parked).contains("AWAITING_APPROVAL");
          assertThat(REFUNDS).hasValue(0);
          assertThat(ctx.getBean(ApprovalService.class).pending(10)).hasSize(1);
          assertThat(ctx.getBean(AuditReader.class).latest(10)).hasSize(2);
        });
  }

  @Test // H1 flipped: resume runs the parking caller's ToolContext under the parking caller's
  // identity
  void resume_runs_with_the_parking_callers_tool_context_and_identity() {
    runner.run(
        ctx -> {
          REFUNDS.set(0);
          var manager = ctx.getBean(ToolCallingManager.class);
          var callbacks = ctx.getBean(ToolCallbackProvider.class).getToolCallbacks();

          loginAs("bob", "SUPPORT");
          assertThat(
                  runToolCall(
                      manager,
                      callbacks,
                      "refundOrder",
                      "{\"orderId\":\"1\"}",
                      Map.of("tenantId", "acme")))
              .contains("AWAITING_APPROVAL");
          loginAs("carol", "SUPPORT");
          runToolCall(
              manager,
              callbacks,
              "refundOrder",
              "{\"orderId\":\"2\"}",
              Map.of("tenantId", "globex"));

          var approvals = ctx.getBean(ApprovalService.class);
          var bobs =
              approvals.pending(10).stream()
                  .filter(d -> d.principal().id().equals("bob"))
                  .findFirst()
                  .orElseThrow();

          loginAs("alice", "APPROVER");
          var outcome = approvals.approve(bobs.id(), "alice", bobs.argsHash());
          assertThat(outcome.result().toModelText())
              .contains("refunded 1")
              .contains("tenant=acme")
              .contains("runAs=bob");
          // the approver's own context is restored afterwards
          assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
              .isEqualTo("alice");
          assertThat(REFUNDS).hasValue(1);
        });
  }

  @Test // M6 flipped: guard failures are structured, internal details stay server-side
  void guard_infrastructure_failure_is_a_structured_error_without_internal_details() {
    runner
        .withUserConfiguration(BrokenAuditConfig.class)
        .run(
            ctx -> {
              REFUNDS.set(0);
              var manager = ctx.getBean(ToolCallingManager.class);
              var callbacks = ctx.getBean(ToolCallbackProvider.class).getToolCallbacks();
              loginAs("bob", "SUPPORT");
              var out =
                  runToolCall(manager, callbacks, "refundOrder", "{\"orderId\":\"1\"}", Map.of());
              assertThat(out)
                  .contains("GUARD_UNAVAILABLE")
                  .contains("AG-GUARD-001")
                  .contains("correlationId")
                  .doesNotContain("db.internal")
                  .doesNotContain("agentguard)")
                  .doesNotContain("Exception");
              assertThat(REFUNDS).hasValue(0);
            });
  }
}

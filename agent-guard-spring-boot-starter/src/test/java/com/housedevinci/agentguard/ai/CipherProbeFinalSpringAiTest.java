package com.housedevinci.agentguard.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.security.PrincipalResolver;
import com.housedevinci.agentguard.security.RunAsAuthentication;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Cipher final-pass probes: (1) Spring AI's real ToolCallingAutoConfiguration (put on the test
 * classpath with -Dmaven.test.additionalClasspath=...spring-ai-autoconfigure-model-tool-2.0.1.jar)
 * applies spring.ai.tools.limits.* with the guard on; (2) RunAsAuthentication forgeability.
 */
class CipherProbeFinalSpringAiTest {

  static final AtomicInteger REFUNDS = new AtomicInteger();

  static class OrderTools {
    @Tool(description = "Refund an order")
    @ToolPolicy(roles = "SUPPORT", sideEffect = SideEffect.DESTRUCTIVE)
    public String refundOrder(String orderId) {
      REFUNDS.incrementAndGet();
      return "refunded " + orderId;
    }
  }

  @AfterEach
  void clear() {
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

  @Test
  void real_spring_ai_tool_autoconfiguration_limits_apply_with_the_guard_on() throws Exception {
    String name = "org.springframework.ai.model.tool.autoconfigure.ToolCallingAutoConfiguration";
    org.junit.jupiter.api.Assumptions.assumeTrue(
        org.springframework.util.ClassUtils.isPresent(name, null),
        "run with -Dmaven.test.additionalClasspath=<spring-ai-autoconfigure-model-tool-2.0.1.jar>");
    Class<?> springAi = Class.forName(name);
    new ApplicationContextRunner()
        .withConfiguration(
            AutoConfigurations.of(
                AgentGuardAutoConfiguration.class,
                AgentGuardSpringAiAutoConfiguration.class,
                springAi))
        .withBean(OrderTools.class)
        .withPropertyValues(
            "agentguard.enabled=true",
            "agentguard.store=MEMORY",
            "spring.ai.tools.limits.max-total-tool-calls=1",
            "spring.ai.tools.limits.on-limit-exceeded=RETURN_ERROR_RESPONSE")
        .run(
            ctx -> {
              REFUNDS.set(0);
              assertThat(ctx.getBeansOfType(ToolCallingManager.class)).hasSize(1);
              var manager = ctx.getBean(ToolCallingManager.class);
              assertThat(manager).isInstanceOf(GuardedToolCallingManager.class);
              assertThat(((GuardedToolCallingManager) manager).delegate())
                  .isInstanceOf(DefaultToolCallingManager.class);
              // the guarded default did not step in: Spring AI's bean definition is the delegate
              assertThat(ctx.containsBean("agentGuardToolCallingManager")).isFalse();
              assertThat(ctx.containsBean("toolCallingManager")).isTrue();

              loginAs("bob", "SUPPORT");
              var options =
                  ToolCallingChatOptions.builder()
                      .toolCallbacks(ToolCallbacks.from(new OrderTools()))
                      .toolContext(Map.of())
                      .build();
              var prompt = new Prompt(new UserMessage("twice"), options);
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
              System.out.println("responses: " + texts);
              assertThat(texts.get(0)).contains("AWAITING_APPROVAL");
              assertThat(texts.get(1)).doesNotContain("AWAITING_APPROVAL");
              assertThat(String.join(" ", texts)).containsIgnoringCase("limit");
              assertThat(REFUNDS).hasValue(0);
            });
  }

  @Test
  void probe_run_as_token_is_publicly_constructible_serializable_and_fully_trusted()
      throws Exception {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class))
        .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY")
        .run(
            ctx -> {
              var ctor = RunAsAuthentication.class.getConstructor(Principal.class);
              assertThat(Modifier.isPublic(ctor.getModifiers())).isTrue();
              var forged =
                  new RunAsAuthentication(
                      new Principal("root", Set.of("ADMIN"), Set.of("all"), "victim-tenant"));
              // it cannot come back from a session store: the Principal record is not Serializable
              var bytes = new ByteArrayOutputStream();
              org.assertj.core.api.Assertions.assertThatThrownBy(
                      () -> new ObjectOutputStream(bytes).writeObject(forged))
                  .isInstanceOf(java.io.NotSerializableException.class);
              // but any code inside the JVM can mint one and it is trusted verbatim
              assertThat(forged.isAuthenticated()).isTrue();
              SecurityContextHolder.getContext().setAuthentication(forged);
              var seen = ctx.getBean(PrincipalResolver.class).resolve();
              assertThat(seen.id()).isEqualTo("root");
              assertThat(seen.roles()).contains("ADMIN");
              assertThat(seen.tenantId()).contains("victim-tenant");
            });
  }
}

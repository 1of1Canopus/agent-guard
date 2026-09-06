package com.housedevinci.agentguard.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.application.BudgetEnforcer;
import com.housedevinci.agentguard.application.GuardResult;
import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.metadata.ChatResponseMetadata;
import org.springframework.ai.chat.metadata.DefaultUsage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

/** I8: the advisor records model usage against TOKENS budgets through a ChatClient. */
class AgentGuardUsageAdvisorTest {

  /** A model that always reports 600 tokens. */
  static final ChatModel FAKE =
      prompt ->
          new ChatResponse(
              List.of(new Generation(new AssistantMessage("ok"))),
              ChatResponseMetadata.builder().usage(new DefaultUsage(400, 200)).build());

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void tokens_are_recorded_and_the_budget_blocks_the_next_tool_call() {
    new ApplicationContextRunner()
        .withConfiguration(
            AutoConfigurations.of(
                AgentGuardAutoConfiguration.class,
                AgentGuardSpringAiAutoConfiguration.class,
                AgentGuardChatClientAutoConfiguration.class))
        .withPropertyValues(
            "agentguard.enabled=true", "agentguard.store=MEMORY",
            "agentguard.budgets.limits[0].scope=PRINCIPAL",
                "agentguard.budgets.limits[0].kind=TOKENS",
            "agentguard.budgets.limits[0].window=P1D", "agentguard.budgets.limits[0].limit=1000")
        .run(
            ctx -> {
              var auth = new TestingAuthenticationToken("bob", "n/a", "ROLE_USER");
              auth.setAuthenticated(true);
              SecurityContextHolder.getContext().setAuthentication(auth);
              var advisor = ctx.getBean(AgentGuardUsageAdvisor.class);
              var client = ChatClient.builder(FAKE).defaultAdvisors(advisor).build();
              ctx.getBean(ToolPolicyRegistry.class)
                  .register("t", PolicyRule.unrestricted(SideEffect.READ));
              var guard = ctx.getBean(ToolGuard.class);
              var principal =
                  ctx.getBean(com.housedevinci.agentguard.security.PrincipalResolver.class)
                      .resolve();

              assertThat(client.prompt("hi").call().content()).isEqualTo("ok"); // 600 tokens
              assertThat(
                      guard.execute(
                          ToolInvocation.of(principal, "t", "{}"), Optional.empty(), a -> "x"))
                  .isInstanceOf(GuardResult.Executed.class);
              assertThat(client.prompt("again").call().content()).isEqualTo("ok"); // 1200 > 1000
              var blocked =
                  guard.execute(
                      ToolInvocation.of(principal, "t", "{}"), Optional.empty(), a -> "x");
              assertThat(blocked).isInstanceOf(GuardResult.BudgetExceeded.class);
              assertThat(blocked.toModelText()).contains("TOKENS");
              assertThat(ctx.getBean(BudgetEnforcer.class).limits()).hasSize(1);
            });
  }
}

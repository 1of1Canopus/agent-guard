package com.housedevinci.agentguard.ai;

import com.housedevinci.agentguard.application.BudgetEnforcer;
import com.housedevinci.agentguard.security.PrincipalResolver;
import java.util.Map;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisor;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisor;
import org.springframework.ai.chat.client.advisor.api.StreamAdvisorChain;
import org.springframework.ai.chat.metadata.Usage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.core.Ordered;
import reactor.core.publisher.Flux;

/**
 * Records the tokens each model response consumed against the {@code TOKENS} budgets, so {@code
 * kind: TOKENS} limits work without any code in the application. Register it as a default advisor
 * ({@code ChatClient.builder(model).defaultAdvisors(advisor)}) or let the auto-configuration expose
 * it as a bean. A TOKENS check admits one more call and can overshoot by that call's tokens.
 */
public final class AgentGuardUsageAdvisor implements CallAdvisor, StreamAdvisor {

  public static final String CONVERSATION_ID_KEY = GuardedToolCallback.CONVERSATION_ID_KEY;

  private final BudgetEnforcer budgets;
  private final PrincipalResolver principals;

  public AgentGuardUsageAdvisor(BudgetEnforcer budgets, PrincipalResolver principals) {
    this.budgets = budgets;
    this.principals = principals;
  }

  @Override
  public String getName() {
    return "agentguard-usage";
  }

  @Override
  public int getOrder() {
    return Ordered.LOWEST_PRECEDENCE - 1000;
  }

  @Override
  public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
    var response = chain.nextCall(request);
    record(request, response.chatResponse());
    return response;
  }

  @Override
  public Flux<ChatClientResponse> adviseStream(
      ChatClientRequest request, StreamAdvisorChain chain) {
    return chain.nextStream(request).doOnNext(r -> record(request, r.chatResponse()));
  }

  private void record(ChatClientRequest request, ChatResponse response) {
    if (response == null || response.getMetadata() == null) {
      return;
    }
    Usage usage = response.getMetadata().getUsage();
    if (usage == null || usage.getTotalTokens() == null) {
      return;
    }
    Map<String, Object> ctx = request.context();
    Object conversation = ctx.get(CONVERSATION_ID_KEY);
    if (conversation == null) {
      conversation = ctx.get(GuardedToolCallback.CHAT_MEMORY_KEY);
    }
    budgets.recordTokens(
        principals.resolve(),
        conversation == null ? null : conversation.toString(),
        usage.getTotalTokens());
  }
}

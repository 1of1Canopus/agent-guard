package com.housedevinci.agentguard.ai;

import java.util.List;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.model.tool.ToolExecutionResult;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;

/**
 * The chokepoint: every {@code ToolCallback} the manager is about to execute, whether it came from
 * a bean, {@code ChatClient.prompt().tools(obj)}, {@code ToolCallbacks.from(...)} or a {@code
 * FunctionToolCallback} built inline, is wrapped before execution.
 */
public final class GuardedToolCallingManager implements ToolCallingManager {

  private final ToolCallingManager delegate;
  private final AgentGuard agentGuard;

  public GuardedToolCallingManager(ToolCallingManager delegate, AgentGuard agentGuard) {
    this.delegate = delegate;
    this.agentGuard = agentGuard;
  }

  public ToolCallingManager delegate() {
    return delegate;
  }

  @Override
  public List<ToolDefinition> resolveToolDefinitions(ToolCallingChatOptions chatOptions) {
    return delegate.resolveToolDefinitions(chatOptions);
  }

  @Override
  public ToolExecutionResult executeToolCalls(Prompt prompt, ChatResponse chatResponse) {
    return delegate.executeToolCalls(guard(prompt), chatResponse);
  }

  private Prompt guard(Prompt prompt) {
    if (!(prompt.getOptions() instanceof ToolCallingChatOptions options)
        || options.getToolCallbacks() == null
        || options.getToolCallbacks().isEmpty()) {
      return prompt;
    }
    List<ToolCallback> guarded = agentGuard.guard(options.getToolCallbacks());
    if (!(options.mutate() instanceof ToolCallingChatOptions.Builder<?> builder)) {
      throw new IllegalStateException(
          "agentguard: cannot rebuild " + options.getClass().getName() + " with guarded callbacks");
    }
    return new Prompt(prompt.getInstructions(), builder.toolCallbacks(guarded).build());
  }
}

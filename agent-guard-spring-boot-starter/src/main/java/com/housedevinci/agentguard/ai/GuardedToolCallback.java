package com.housedevinci.agentguard.ai;

import com.housedevinci.agentguard.application.GuardResult;
import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.security.PrincipalResolver;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.metadata.ToolMetadata;

/**
 * Decorates a Spring AI {@link ToolCallback}: policy, approval gate, budget and audit run before
 * the delegate; every refusal is returned to the model as a structured JSON string. The {@link
 * ToolContext} of the parking call is captured with the decision and reused when the approval
 * resumes it. Failures of the guard itself never escape as exceptions.
 *
 * <p>Conversation id is read from the {@link ToolContext} under {@value #CONVERSATION_ID_KEY} or
 * Spring AI's chat-memory key {@value #CHAT_MEMORY_KEY}; both are set by server-side code.
 */
public final class GuardedToolCallback implements ToolCallback {

  private static final Logger log = LoggerFactory.getLogger(GuardedToolCallback.class);

  public static final String CONVERSATION_ID_KEY = "agentguard.conversationId";
  public static final String CHAT_MEMORY_KEY = "chat_memory_conversation_id";
  public static final String CORRELATION_ID_KEY = "agentguard.correlationId";

  private final ToolCallback delegate;
  private final ToolGuard guard;
  private final PrincipalResolver principals;

  public GuardedToolCallback(ToolCallback delegate, ToolGuard guard, PrincipalResolver principals) {
    this.delegate = delegate;
    this.guard = guard;
    this.principals = principals;
  }

  public ToolCallback delegate() {
    return delegate;
  }

  @Override
  public ToolDefinition getToolDefinition() {
    return delegate.getToolDefinition();
  }

  @Override
  public ToolMetadata getToolMetadata() {
    return delegate.getToolMetadata();
  }

  @Override
  public String call(String toolInput) {
    return call(toolInput, null);
  }

  @Override
  public String call(String toolInput, ToolContext toolContext) {
    String toolName = delegate.getToolDefinition().name();
    String correlationId = UUID.randomUUID().toString();
    try {
      Map<String, Object> ctx = toolContext == null ? Map.of() : toolContext.getContext();
      var invocation =
          new ToolInvocation(
              principals.resolve(),
              toolName,
              toolInput,
              string(ctx.get(CONVERSATION_ID_KEY), ctx.get(CHAT_MEMORY_KEY)),
              string(ctx.get(CORRELATION_ID_KEY), correlationId));
      GuardResult result =
          guard.execute(
              invocation,
              Optional.empty(),
              args -> toolContext == null ? delegate.call(args) : delegate.call(args, toolContext));
      return result.toModelText();
    } catch (RuntimeException e) {
      log.error(
          "agentguard: guard unavailable for tool '{}' correlationId={}",
          toolName,
          correlationId,
          e);
      return new GuardResult.GuardUnavailable(toolName, correlationId).toModelText();
    }
  }

  private static String string(Object... candidates) {
    for (Object c : candidates) {
      if (c != null) {
        return c.toString();
      }
    }
    return null;
  }
}

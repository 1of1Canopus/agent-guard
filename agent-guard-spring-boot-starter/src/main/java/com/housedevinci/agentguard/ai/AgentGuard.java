package com.housedevinci.agentguard.ai;

import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.security.PrincipalResolver;
import java.util.Arrays;
import java.util.List;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;

/**
 * Programmatic decoration for callbacks that do not pass through the bean lifecycle (for example
 * {@code ChatClient.prompt().toolCallbacks(agentGuard.guard(callbacks))}).
 */
public final class AgentGuard {

  private final ToolGuard guard;
  private final PrincipalResolver principals;

  public AgentGuard(ToolGuard guard, PrincipalResolver principals) {
    this.guard = guard;
    this.principals = principals;
  }

  public ToolCallback guard(ToolCallback callback) {
    return callback instanceof GuardedToolCallback ? callback : new GuardedToolCallback(callback, guard, principals);
  }

  public List<ToolCallback> guard(List<? extends ToolCallback> callbacks) {
    return callbacks.stream().map(this::guard).toList();
  }

  public ToolCallback[] guard(ToolCallback... callbacks) {
    return Arrays.stream(callbacks).map(this::guard).toArray(ToolCallback[]::new);
  }

  public ToolCallbackProvider guard(ToolCallbackProvider provider) {
    return provider instanceof GuardedToolCallbackProvider ? provider : new GuardedToolCallbackProvider(provider, this);
  }

  /** Wraps every callback a provider returns. */
  public static final class GuardedToolCallbackProvider implements ToolCallbackProvider {
    private final ToolCallbackProvider delegate;
    private final AgentGuard agentGuard;

    GuardedToolCallbackProvider(ToolCallbackProvider delegate, AgentGuard agentGuard) {
      this.delegate = delegate;
      this.agentGuard = agentGuard;
    }

    @Override
    public ToolCallback[] getToolCallbacks() {
      return agentGuard.guard(delegate.getToolCallbacks());
    }
  }

  public ToolGuard toolGuard() {
    return guard;
  }
}

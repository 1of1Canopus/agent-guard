package com.housedevinci.agentguard.ai;

import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.autoconfigure.GuardCoverage;
import com.housedevinci.agentguard.security.PrincipalResolver;
import java.util.Arrays;
import java.util.List;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;

/**
 * Programmatic decoration for callbacks that do not pass through the bean lifecycle (for example
 * {@code ChatClient.prompt().toolCallbacks(agentGuard.guard(callbacks))}). Idempotent.
 */
public final class AgentGuard {

  private final ToolGuard guard;
  private final PrincipalResolver principals;
  private final GuardCoverage coverage;

  public AgentGuard(ToolGuard guard, PrincipalResolver principals, GuardCoverage coverage) {
    this.guard = guard;
    this.principals = principals;
    this.coverage = coverage;
  }

  public ToolCallback guard(ToolCallback callback) {
    if (callback instanceof GuardedToolCallback) {
      return callback;
    }
    coverage.guarded(callback.getToolDefinition().name(), GuardCoverage.Path.SPRING_AI);
    return new GuardedToolCallback(callback, guard, principals);
  }

  public List<ToolCallback> guard(List<? extends ToolCallback> callbacks) {
    return callbacks.stream().map(this::guard).toList();
  }

  public ToolCallback[] guard(ToolCallback... callbacks) {
    return Arrays.stream(callbacks).map(this::guard).toArray(ToolCallback[]::new);
  }

  public ToolCallbackProvider guard(ToolCallbackProvider provider) {
    if (provider instanceof GuardedToolCallbackProvider) {
      return provider;
    }
    for (ToolCallback cb : provider.getToolCallbacks()) {
      coverage.guarded(cb.getToolDefinition().name(), GuardCoverage.Path.SPRING_AI);
    }
    return new GuardedToolCallbackProvider(provider, this);
  }

  public ToolCallingManager guard(ToolCallingManager manager) {
    coverage.springAiChokepointActive();
    return manager instanceof GuardedToolCallingManager
        ? manager
        : new GuardedToolCallingManager(manager, this);
  }

  public ToolCallbackResolver guard(ToolCallbackResolver resolver) {
    if (resolver instanceof GuardedToolCallbackResolver) {
      return resolver;
    }
    return new GuardedToolCallbackResolver(resolver, this);
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

  /** Wraps every callback resolved by name (function beans). */
  public static final class GuardedToolCallbackResolver implements ToolCallbackResolver {
    private final ToolCallbackResolver delegate;
    private final AgentGuard agentGuard;

    GuardedToolCallbackResolver(ToolCallbackResolver delegate, AgentGuard agentGuard) {
      this.delegate = delegate;
      this.agentGuard = agentGuard;
    }

    @Override
    public ToolCallback resolve(String toolName) {
      ToolCallback cb = delegate.resolve(toolName);
      return cb == null ? null : agentGuard.guard(cb);
    }
  }

  public ToolGuard toolGuard() {
    return guard;
  }
}

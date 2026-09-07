package com.housedevinci.agentguard.domain;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Programmatic policy registry: tool name to {@link PolicyRule}. Filled from {@code @ToolPolicy}
 * annotations at startup and by application code for tools that have no annotation.
 */
public final class ToolPolicyRegistry {

  private final Map<String, PolicyRule> rules = new ConcurrentHashMap<>();

  /**
   * Registers a rule. Registering the identical rule again is a no-op; a different rule for a name
   * that already has one is a configuration error (two beans, two policies, one tool).
   */
  public ToolPolicyRegistry register(String toolName, PolicyRule rule) {
    Objects.requireNonNull(toolName, "toolName");
    Objects.requireNonNull(rule, "rule");
    PolicyRule existing = rules.putIfAbsent(toolName, rule);
    if (existing != null && !existing.equals(rule)) {
      throw new IllegalStateException(
          "tool '"
              + toolName
              + "' already has a different @ToolPolicy: "
              + existing
              + " vs "
              + rule);
    }
    return this;
  }

  /** Replaces whatever rule the name has (programmatic overrides). */
  public ToolPolicyRegistry override(String toolName, PolicyRule rule) {
    rules.put(Objects.requireNonNull(toolName, "toolName"), Objects.requireNonNull(rule, "rule"));
    return this;
  }

  public Optional<PolicyRule> find(String toolName) {
    return Optional.ofNullable(rules.get(toolName));
  }

  public Map<String, PolicyRule> all() {
    return Map.copyOf(rules);
  }
}

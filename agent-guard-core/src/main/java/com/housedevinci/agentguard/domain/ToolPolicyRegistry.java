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

  public ToolPolicyRegistry register(String toolName, PolicyRule rule) {
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

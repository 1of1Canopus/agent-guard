package com.housedevinci.agentguard.autoconfigure;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * What the guard actually intercepts: the tool names wrapped through each path, plus whether the
 * Spring AI {@code ToolCallingManager} chokepoint is active (then every {@code @Tool} reaches the
 * guard whatever way it was built). Compared against the scanned policies at startup.
 */
public final class GuardCoverage {

  public enum Path {
    SPRING_AI,
    MCP,
    PROGRAMMATIC
  }

  /** Where a scanned policy sits. */
  public enum Declared {
    TOOL,
    MCP_TOOL,
    PLAIN_METHOD
  }

  private final Set<String> guarded = ConcurrentHashMap.newKeySet();
  private final Map<String, Declared> policies = new ConcurrentHashMap<>();
  private volatile boolean springAiChokepoint;

  public void guarded(String toolName, Path path) {
    guarded.add(toolName);
  }

  public void declared(String toolName, Declared where) {
    policies.put(toolName, where);
  }

  public void springAiChokepointActive() {
    this.springAiChokepoint = true;
  }

  public boolean isSpringAiChokepointActive() {
    return springAiChokepoint;
  }

  public Set<String> guardedTools() {
    return Collections.unmodifiableSet(guarded);
  }

  public Map<String, Declared> declaredPolicies() {
    return Collections.unmodifiableMap(policies);
  }

  /** Policies not reachable through a guarded path. */
  public Set<String> unguardedPolicies() {
    Set<String> out = new java.util.TreeSet<>();
    policies.forEach(
        (name, where) -> {
          boolean covered =
              guarded.contains(name) || (where == Declared.TOOL && springAiChokepoint);
          if (!covered) {
            out.add(name);
          }
        });
    return out;
  }
}

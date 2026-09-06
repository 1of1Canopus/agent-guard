package com.housedevinci.agentguard.application;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tool name to executor, so an approved decision can be resumed later from a different thread (the
 * approval endpoint) than the one that parked it.
 */
public final class ToolExecutorRegistry {

  private final Map<String, ToolExecutor> executors = new ConcurrentHashMap<>();

  public void register(String toolName, ToolExecutor executor) {
    executors.put(Objects.requireNonNull(toolName), Objects.requireNonNull(executor));
  }

  public Optional<ToolExecutor> find(String toolName) {
    return Optional.ofNullable(executors.get(toolName));
  }
}

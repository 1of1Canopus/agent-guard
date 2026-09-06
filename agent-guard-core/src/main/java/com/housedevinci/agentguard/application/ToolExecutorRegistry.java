package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.DecisionId;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Decision id to the executor captured when that decision was parked (the parking caller's tool
 * context / MCP exchange), so the approval can run exactly that closure later, from another thread.
 * In-memory: after a restart the decision can no longer be resumed ({@code AG-APPROVAL-007}).
 */
public final class ToolExecutorRegistry {

  private final Map<DecisionId, ToolExecutor> executors = new ConcurrentHashMap<>();

  public void register(DecisionId decisionId, ToolExecutor executor) {
    executors.put(Objects.requireNonNull(decisionId), Objects.requireNonNull(executor));
  }

  public Optional<ToolExecutor> find(DecisionId decisionId) {
    return Optional.ofNullable(executors.get(decisionId));
  }

  public void remove(DecisionId decisionId) {
    executors.remove(decisionId);
  }

  public int size() {
    return executors.size();
  }
}

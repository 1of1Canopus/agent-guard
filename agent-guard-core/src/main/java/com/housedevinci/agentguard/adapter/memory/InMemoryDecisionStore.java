package com.housedevinci.agentguard.adapter.memory;

import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.PendingDecision;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Thread-safe in-memory store for tests and single-node development. Not for production. */
public final class InMemoryDecisionStore implements DecisionStore {

  private final Map<DecisionId, PendingDecision> byId = new ConcurrentHashMap<>();

  @Override
  public void save(PendingDecision decision) {
    byId.put(decision.id(), decision);
  }

  @Override
  public Optional<PendingDecision> findById(DecisionId id) {
    return Optional.ofNullable(byId.get(id));
  }

  @Override
  public Optional<PendingDecision> findLatest(String principalId, String tool, String argsHash) {
    return byId.values().stream()
        .filter(d -> d.principal().id().equals(principalId))
        .filter(d -> d.tool().name().equals(tool))
        .filter(d -> d.argsHash().equals(argsHash))
        .max(Comparator.comparing(PendingDecision::createdAt));
  }

  @Override
  public List<PendingDecision> findByState(DecisionState state, int limit) {
    return byId.values().stream()
        .filter(d -> d.state() == state)
        .sorted(Comparator.comparing(PendingDecision::createdAt))
        .limit(limit)
        .toList();
  }

  @Override
  public boolean transition(
      DecisionId id, DecisionState expected, DecisionState target, String by, Instant at) {
    var result = new boolean[1];
    byId.computeIfPresent(
        id,
        (k, d) -> {
          if (d.state() != expected) {
            return d;
          }
          result[0] = true;
          return d.decide(target, by, at);
        });
    return result[0];
  }

  @Override
  public boolean markExecutedOnce(DecisionId id) {
    var result = new boolean[1];
    byId.computeIfPresent(
        id,
        (k, d) -> {
          if (d.executed()) {
            return d;
          }
          result[0] = true;
          return d.withExecuted(null);
        });
    return result[0];
  }

  @Override
  public void storeResult(DecisionId id, String resultJson) {
    byId.computeIfPresent(id, (k, d) -> d.withExecuted(resultJson));
  }
}

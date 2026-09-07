package com.housedevinci.agentguard.domain;

import java.util.Objects;
import java.util.UUID;

/** Single-use identifier of a parked tool call. */
public record DecisionId(UUID value) {
  public DecisionId {
    Objects.requireNonNull(value, "decision id");
  }

  public static DecisionId random() {
    return new DecisionId(UUID.randomUUID());
  }

  public static DecisionId of(String text) {
    return new DecisionId(UUID.fromString(text));
  }

  @Override
  public String toString() {
    return value.toString();
  }
}

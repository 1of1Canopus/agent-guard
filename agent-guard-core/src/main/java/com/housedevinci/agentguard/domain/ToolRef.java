package com.housedevinci.agentguard.domain;

import java.util.Objects;

/** A tool as seen by the guard: its name and the side effect it is declared to have. */
public record ToolRef(String name, SideEffect sideEffect) {
  public ToolRef {
    Objects.requireNonNull(name, "tool name");
    Objects.requireNonNull(sideEffect, "side effect");
    if (name.isBlank()) {
      throw new IllegalArgumentException("tool name must not be blank");
    }
  }
}

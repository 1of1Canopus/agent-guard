package com.housedevinci.agentguard.domain;

import java.util.Objects;

/** Root of every typed exception of the module. Carries a stable {@link #code()}. */
public class AgentGuardException extends RuntimeException {

  private final String code;

  public AgentGuardException(String code, String message) {
    super(message);
    this.code = Objects.requireNonNull(code, "code");
  }

  public AgentGuardException(String code, String message, Throwable cause) {
    super(message, cause);
    this.code = Objects.requireNonNull(code, "code");
  }

  public String code() {
    return code;
  }
}

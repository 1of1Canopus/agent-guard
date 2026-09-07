package com.housedevinci.agentguard.domain;

import java.util.Objects;

/** Outcome of evaluating a {@link PolicyRule} for a {@link Principal} and a {@link ToolRef}. */
public sealed interface PolicyDecision {

  enum Kind {
    ALLOW,
    DENY,
    REQUIRE_APPROVAL
  }

  Kind kind();

  /** The call may proceed (budgets still apply). */
  record Allow() implements PolicyDecision {
    @Override
    public Kind kind() {
      return Kind.ALLOW;
    }
  }

  /**
   * The call is refused.
   *
   * @param code stable error code, e.g. {@code AG-POLICY-001}
   * @param reason human-readable reason, safe to return to the model
   */
  record Deny(String code, String reason) implements PolicyDecision {
    public Deny {
      Objects.requireNonNull(code, "code");
      Objects.requireNonNull(reason, "reason");
    }

    @Override
    public Kind kind() {
      return Kind.DENY;
    }
  }

  /** The call must be parked until a human approves it. */
  record RequireApproval() implements PolicyDecision {
    @Override
    public Kind kind() {
      return Kind.REQUIRE_APPROVAL;
    }
  }

  static PolicyDecision allow() {
    return new Allow();
  }

  static PolicyDecision deny(String code, String reason) {
    return new Deny(code, reason);
  }

  static PolicyDecision requireApproval() {
    return new RequireApproval();
  }
}

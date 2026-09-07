package com.housedevinci.agentguard.domain;

/** What the guard decided for one tool invocation. */
public enum AuditDecision {
  ALLOWED,
  DENIED,
  PENDING,
  APPROVED,
  REJECTED,
  EXPIRED,
  BUDGET_EXCEEDED,
  /** Stored arguments no longer match the approved hash; the decision is closed. */
  TAMPERED,
  FAILED
}

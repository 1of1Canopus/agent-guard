package com.housedevinci.agentguard.domain;

/** What a budget counts. */
public enum BudgetKind {
  /** Tool invocations that reached dispatch. */
  TOOL_CALLS,
  /** Agent steps (tool calls) inside one conversation. */
  STEPS,
  /** Model tokens, from Spring AI usage metadata. */
  TOKENS
}

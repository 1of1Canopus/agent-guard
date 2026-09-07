package com.housedevinci.agentguard.application;

/** What to do with a tool that has neither {@code @ToolPolicy} nor a registry entry. */
public enum UnregisteredToolBehaviour {
  /** Refuse the call (fail closed). Default. */
  DENY,
  /** Treat it as a READ tool. */
  ALLOW,
  /** Treat it as a WRITE tool: park for approval. */
  REQUIRE_APPROVAL
}

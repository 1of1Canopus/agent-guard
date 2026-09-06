package com.housedevinci.agentguard.domain;

/** The policy refused the call. Returned to the model as a structured error, never as a trace. */
public final class ToolDeniedException extends AgentGuardException {
  private final String tool;

  public ToolDeniedException(String tool, String code, String reason) {
    super(code, "Tool '" + tool + "' denied: " + reason);
    this.tool = tool;
  }

  public String tool() {
    return tool;
  }
}

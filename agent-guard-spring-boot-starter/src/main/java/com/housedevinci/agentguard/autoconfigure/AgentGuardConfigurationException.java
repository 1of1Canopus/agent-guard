package com.housedevinci.agentguard.autoconfigure;

/** Startup failure naming the property that is wrong. */
public final class AgentGuardConfigurationException extends IllegalStateException {
  public AgentGuardConfigurationException(String message) {
    super(message);
  }
}

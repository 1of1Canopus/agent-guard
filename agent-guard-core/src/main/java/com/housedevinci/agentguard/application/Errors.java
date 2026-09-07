package com.housedevinci.agentguard.application;

/**
 * Renders a tool exception for the model. By default only the exception class and the correlation
 * id: tool authors rarely mean their messages for an untrusted agent. The message goes to the log.
 */
final class Errors {
  private static final int MAX = 300;

  private Errors() {}

  static String describe(Throwable t, String correlationId, boolean includeMessage) {
    var name = t.getClass().getSimpleName();
    if (!includeMessage || t.getMessage() == null) {
      return name + " (correlationId=" + correlationId + ")";
    }
    var msg = name + ": " + t.getMessage();
    return (msg.length() > MAX ? msg.substring(0, MAX) : msg)
        + " (correlationId="
        + correlationId
        + ")";
  }
}

package com.housedevinci.agentguard.application;

/** Renders an exception for the model: class and message only, capped, never a stack trace. */
final class Errors {
  private static final int MAX = 300;

  private Errors() {}

  static String describe(Throwable t) {
    var msg = t.getClass().getSimpleName() + (t.getMessage() == null ? "" : ": " + t.getMessage());
    return msg.length() > MAX ? msg.substring(0, MAX) : msg;
  }
}

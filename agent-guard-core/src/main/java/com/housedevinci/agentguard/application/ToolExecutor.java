package com.housedevinci.agentguard.application;

/** Runs the real tool with JSON arguments and returns its text result. */
@FunctionalInterface
public interface ToolExecutor {
  String execute(String argumentsJson) throws Exception;
}

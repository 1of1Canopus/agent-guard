package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.Principal;
import java.util.Objects;
import java.util.UUID;

/**
 * One actual tool call, as intercepted at the boundary.
 *
 * @param principal the caller
 * @param toolName the tool name as the model sees it
 * @param argumentsJson the raw arguments (JSON text)
 * @param conversationId conversation / chat id if known, else null
 * @param correlationId correlation id; generated when null
 */
public record ToolInvocation(
    Principal principal,
    String toolName,
    String argumentsJson,
    String conversationId,
    String correlationId) {

  public ToolInvocation {
    Objects.requireNonNull(principal, "principal");
    Objects.requireNonNull(toolName, "toolName");
    argumentsJson = Objects.requireNonNullElse(argumentsJson, "");
    correlationId =
        (correlationId == null || correlationId.isBlank())
            ? UUID.randomUUID().toString()
            : correlationId;
  }

  public static ToolInvocation of(Principal principal, String toolName, String argumentsJson) {
    return new ToolInvocation(principal, toolName, argumentsJson, null, null);
  }
}

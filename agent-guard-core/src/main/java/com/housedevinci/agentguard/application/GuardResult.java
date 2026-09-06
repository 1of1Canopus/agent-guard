package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.PendingDecision;

/**
 * What the model receives. {@link Executed} carries the tool's own result untouched; every other
 * variant renders as a structured JSON error object, never a stack trace.
 */
public sealed interface GuardResult {

  /** Text handed back to the model. */
  String toModelText();

  /** True for everything but a successful execution (MCP {@code isError}). */
  boolean isError();

  record Executed(String result) implements GuardResult {
    @Override
    public String toModelText() {
      return result;
    }

    @Override
    public boolean isError() {
      return false;
    }
  }

  record AwaitingApproval(PendingDecision decision) implements GuardResult {
    @Override
    public String toModelText() {
      return Json.object()
          .put("status", "AWAITING_APPROVAL")
          .put("code", ErrorCodes.APPROVAL_PENDING)
          .put("decisionId", decision.id().toString())
          .put("tool", decision.tool().name())
          .put("expiresAt", decision.expiresAt().toString())
          .put(
              "message",
              "This call needs a human approval. Do not retry; tell the user the decision id.")
          .toString();
    }

    @Override
    public boolean isError() {
      return true;
    }
  }

  record Denied(String code, String tool, String message) implements GuardResult {
    @Override
    public String toModelText() {
      return Json.object()
          .put("status", "DENIED")
          .put("error", "TOOL_DENIED")
          .put("code", code)
          .put("tool", tool)
          .put("message", message)
          .toString();
    }

    @Override
    public boolean isError() {
      return true;
    }
  }

  record BudgetExceeded(String tool, String message) implements GuardResult {
    @Override
    public String toModelText() {
      return Json.object()
          .put("status", "DENIED")
          .put("error", "BUDGET_EXCEEDED")
          .put("code", ErrorCodes.BUDGET_EXCEEDED)
          .put("tool", tool)
          .put("message", message)
          .toString();
    }

    @Override
    public boolean isError() {
      return true;
    }
  }

  /** The guard itself (store, audit, notifier, context) failed; the tool did not run. */
  record GuardUnavailable(String tool, String correlationId) implements GuardResult {
    @Override
    public String toModelText() {
      return Json.object()
          .put("status", "ERROR")
          .put("error", "GUARD_UNAVAILABLE")
          .put("code", ErrorCodes.GUARD_UNAVAILABLE)
          .put("tool", tool)
          .put("correlationId", correlationId)
          .put("message", "the tool guard is unavailable; the call was not executed")
          .toString();
    }

    @Override
    public boolean isError() {
      return true;
    }
  }

  record Failed(String tool, String message) implements GuardResult {
    @Override
    public String toModelText() {
      return Json.object()
          .put("status", "ERROR")
          .put("error", "TOOL_FAILED")
          .put("code", ErrorCodes.TOOL_FAILED)
          .put("tool", tool)
          .put("message", message)
          .toString();
    }

    @Override
    public boolean isError() {
      return true;
    }
  }
}

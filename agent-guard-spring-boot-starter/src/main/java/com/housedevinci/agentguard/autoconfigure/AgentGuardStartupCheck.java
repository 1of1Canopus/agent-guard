package com.housedevinci.agentguard.autoconfigure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * After every singleton exists: log what is guarded, warn about configurations that quietly weaken
 * the guard, and in strict mode refuse to start when a tool that carries {@code @ToolPolicy} is not
 * reachable through a guarded path (a silent gap is worse than no guard).
 */
public final class AgentGuardStartupCheck implements SmartInitializingSingleton {

  private static final Logger log = LoggerFactory.getLogger(AgentGuardStartupCheck.class);

  private final GuardCoverage coverage;
  private final AgentGuardProperties props;

  public AgentGuardStartupCheck(GuardCoverage coverage, AgentGuardProperties props) {
    this.coverage = coverage;
    this.props = props;
  }

  @Override
  public void afterSingletonsInstantiated() {
    log.info(
        "agentguard: guarded tools {} (Spring AI chokepoint {}{}), policies {}",
        coverage.guardedTools(),
        coverage.isSpringAiChokepointActive() ? "active" : "inactive",
        coverage.springAiDelegate().isEmpty() ? "" : ", wraps " + coverage.springAiDelegate(),
        coverage.declaredPolicies().keySet());
    if (coverage.isSpringAiChokepointActive()) {
      log.info(
          "agentguard: a ToolCallingManager built by hand and passed to a ChatModel builder is outside"
              + " the guard; use the bean or AgentGuard.guard(manager)");
    }
    if (props.getPolicy().getApprovalRequiredFor().isEmpty()) {
      log.warn(
          "agentguard.policy.approval-required-for is empty: no side effect requires approval;"
              + " DESTRUCTIVE tools run without a human");
    }
    if (props.getRedaction().getSensitiveKeys().isEmpty()) {
      log.warn(
          "agentguard.redaction.sensitive-keys is empty: nothing is masked in previews, logs and webhooks");
    }
    var gaps = coverage.unguardedPolicies();
    if (gaps.isEmpty()) {
      return;
    }
    String message =
        "agentguard.strict=true: tools with @ToolPolicy are not reachable through a guarded path: "
            + gaps
            + ". Expose them as ToolCallback/ToolCallbackProvider/@McpTool beans, use the"
            + " ToolCallingManager bean, or set agentguard.strict=false to only warn.";
    if (props.isStrict()) {
      throw new AgentGuardConfigurationException(message);
    }
    log.warn(message);
  }
}

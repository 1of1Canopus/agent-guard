package com.housedevinci.agentguard.autoconfigure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * After every singleton exists: log what is guarded and, in strict mode, refuse to start when a
 * tool that carries {@code @ToolPolicy} is not reachable through a guarded path (a silent gap is
 * worse than no guard at all).
 */
public final class AgentGuardStartupCheck implements SmartInitializingSingleton {

  private static final Logger log = LoggerFactory.getLogger(AgentGuardStartupCheck.class);

  private final GuardCoverage coverage;
  private final boolean strict;

  public AgentGuardStartupCheck(GuardCoverage coverage, boolean strict) {
    this.coverage = coverage;
    this.strict = strict;
  }

  @Override
  public void afterSingletonsInstantiated() {
    log.info(
        "agentguard: guarded tools {} (Spring AI chokepoint {}), policies {}",
        coverage.guardedTools(),
        coverage.isSpringAiChokepointActive() ? "active" : "inactive",
        coverage.declaredPolicies().keySet());
    var gaps = coverage.unguardedPolicies();
    if (gaps.isEmpty()) {
      return;
    }
    String message =
        "agentguard.strict=true: tools with @ToolPolicy are not reachable through a guarded path: "
            + gaps
            + ". Expose them as ToolCallback/ToolCallbackProvider/@McpTool beans, use the"
            + " ToolCallingManager bean, or set agentguard.strict=false to only warn.";
    if (strict) {
      throw new AgentGuardConfigurationException(message);
    }
    log.warn(message);
  }
}

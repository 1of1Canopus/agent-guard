package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * the security review re-verification of {@code 6f026ff}. Asserts the behaviour as it is today (the vulnerable
 * one); engineering flips the assertion when the fix lands.
 */
class CipherProbeReverifyStartupTest {

  /**
   * V4 (LOW, new in C9). {@code AgentGuardStartupCheck} exists to "warn about configurations that
   * quietly weaken the guard" and does so for an empty {@code approval-required-for}, empty {@code
   * sensitive-keys}, {@code store=MEMORY}, a missing notifier, a missing {@code TenantResolver} and
   * a runtime role that owns the audit table. The two switches C9 introduced or relies on — {@code
   * agentguard.endpoints.tenant-scoped=false} and {@code agentguard.endpoints.require-tenant=false}
   * — turn a tenant-less approver back into a cross-tenant approver and are the loudest thing in
   * the module that is completely silent. The sample opts out in a YAML comment only; nothing in a
   * running process says so.
   *
   * <p>Fix: in {@code AgentGuardStartupCheck.afterSingletonsInstantiated}, when {@code
   * endpoints.enabled} and either {@code !tenantScoped} or {@code !requireTenant}, {@code log.warn}
   * naming the property and the consequence ("approvers see and decide every tenant's decisions and
   * audit rows"). Test: flip this probe to assert the warning is present.
   */
  @Test
  void probe_a_cross_tenant_approver_opt_out_is_silent_at_startup() {
    var props = new AgentGuardProperties();
    props.getEndpoints().setEnabled(true);
    props.getEndpoints().setTenantScoped(false);
    props.getEndpoints().setRequireTenant(false);
    // one configuration the check *does* warn about, so the appender is proven to be wired
    props.getRedaction().setSensitiveKeys(java.util.Set.of());

    var logger = (Logger) LoggerFactory.getLogger(AgentGuardStartupCheck.class);
    var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    try {
      new AgentGuardStartupCheck(new GuardCoverage(), props).afterSingletonsInstantiated();
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }

    List<String> warnings =
        appender.list.stream()
            .filter(e -> e.getLevel() == Level.WARN)
            .map(ILoggingEvent::getFormattedMessage)
            .toList();
    assertThat(warnings)
        .as("the appender is wired: the check warns about the empty sensitive-keys list")
        .anyMatch(m -> m.contains("sensitive-keys"));
    assertThat(warnings)
        .as("nothing warns that approvers are cross-tenant")
        .noneMatch(m -> m.contains("tenant-scoped") || m.contains("require-tenant"));
  }
}

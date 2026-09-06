package com.housedevinci.agentguard.adapter.notify;

import com.housedevinci.agentguard.domain.Notifier;
import com.housedevinci.agentguard.domain.PendingDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Logs the parked call at WARN. The preview is already redacted and stripped of control chars. */
public final class LoggingNotifier implements Notifier {

  private static final Logger log = LoggerFactory.getLogger("agentguard.approval");

  @Override
  public void notify(PendingDecision d) {
    log.warn(
        "Tool call awaiting approval: decision={} tool={} principal={} tenant={} expiresAt={} args={}",
        d.id(),
        d.tool().name(),
        d.principal().id(),
        d.principal().tenantId().orElse("-"),
        d.expiresAt(),
        d.argsPreview());
  }
}

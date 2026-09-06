package com.housedevinci.agentguard.adapter.notify;

import com.housedevinci.agentguard.domain.Notifier;
import com.housedevinci.agentguard.domain.PendingDecision;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Fans out to several notifiers; one failing never stops the others. */
public final class CompositeNotifier implements Notifier {

  private static final Logger log = LoggerFactory.getLogger(CompositeNotifier.class);

  private final List<Notifier> delegates;

  public CompositeNotifier(List<Notifier> delegates) {
    this.delegates = List.copyOf(delegates);
  }

  @Override
  public void notify(PendingDecision decision) {
    for (Notifier n : delegates) {
      try {
        n.notify(decision);
      } catch (RuntimeException e) {
        log.warn("Notifier {} failed for decision {}: {}", n.getClass().getSimpleName(), decision.id(), e.toString());
      }
    }
  }
}

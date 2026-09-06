package com.housedevinci.agentguard.adapter.memory;

import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import java.util.ArrayList;
import java.util.List;

/** Append-only, hash-chained, in memory. For tests and development. */
public final class InMemoryAuditSink implements AuditSink, AuditReader {

  private final List<AuditEvent> events = new ArrayList<>();

  @Override
  public synchronized AuditEvent append(AuditEvent event) {
    String prev = events.isEmpty() ? AuditChain.GENESIS : events.get(events.size() - 1).hash();
    var linked = AuditChain.link(event.withSequence(events.size() + 1L), prev);
    events.add(linked);
    return linked;
  }

  @Override
  public synchronized List<AuditEvent> readAfter(long afterSequence, int limit) {
    return events.stream().filter(e -> e.sequence() > afterSequence).limit(limit).toList();
  }

  @Override
  public synchronized List<AuditEvent> latest(int limit) {
    var copy = new ArrayList<>(events);
    java.util.Collections.reverse(copy);
    return copy.stream().limit(limit).toList();
  }

  /** Test hook: replaces a row in place to simulate tampering. */
  public synchronized void tamper(int index, AuditEvent replacement) {
    events.set(index, replacement);
  }
}

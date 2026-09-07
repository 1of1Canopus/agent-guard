package com.housedevinci.agentguard.adapter.memory;

import com.housedevinci.agentguard.domain.AuditAnchor;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import java.util.ArrayList;
import java.util.List;

/** Append-only, hash-chained, in memory. For tests and development. */
public final class InMemoryAuditSink implements AuditSink, AuditReader, AuditAnchor {

  private final List<AuditEvent> events = new ArrayList<>();
  private final AuditChain chain;

  /**
   * V2 (QUESTIONS.md #20): {@code null} until the first row is appended under a keyed chain, then
   * the sequence of that row, mirroring {@code agentguard_audit_anchor.keyed_from_seq} — set once,
   * never moved. Lives outside {@link #events}, so the {@link #tamper} test hook (which stands in
   * for a table-owning attacker's row-level rewrite) cannot touch it, the same way a raw {@code
   * UPDATE agentguard_audit} cannot touch the anchor row.
   */
  private Long keyedFromSeq;

  public InMemoryAuditSink() {
    this(AuditChain.unkeyed());
  }

  public InMemoryAuditSink(AuditChain chain) {
    this.chain = chain;
  }

  /**
   * Continues an existing trail (e.g. one produced by another {@code InMemoryAuditSink}) under
   * {@code chain}, the in-memory analogue of a new {@code JdbcAuditSink} instance starting against
   * a table another instance already wrote to — the scenario behind "enabling {@code
   * agentguard.audit.hmac-secret} on a running installation" (the security review C6). {@code keyedFromSeq} is
   * re-derived from {@code existing} exactly like {@code JdbcAuditSink.append} does for a trail
   * whose anchor row is missing, so a genuinely-keyed prefix carried over from the source sink is
   * not forgotten.
   */
  public InMemoryAuditSink(List<AuditEvent> existing, AuditChain chain) {
    this.events.addAll(existing);
    this.chain = chain;
    this.keyedFromSeq =
        existing.stream()
            .filter(e -> AuditChain.KEYED_VERSION.equals(e.version()))
            .map(AuditEvent::sequence)
            .min(Long::compareTo)
            .orElse(null);
  }

  @Override
  public synchronized AuditEvent append(AuditEvent event) {
    String prev = events.isEmpty() ? AuditChain.GENESIS : events.get(events.size() - 1).hash();
    var linked = chain.linkEvent(event.withSequence(events.size() + 1L), prev);
    events.add(linked);
    if (keyedFromSeq == null && AuditChain.KEYED_VERSION.equals(linked.version())) {
      keyedFromSeq = linked.sequence();
    }
    return linked;
  }

  @Override
  public synchronized List<AuditEvent> readAfter(long afterSequence, int limit) {
    return events.stream().filter(e -> e.sequence() > afterSequence).limit(limit).toList();
  }

  @Override
  public synchronized List<AuditEvent> latest(String tenantId, int limit) {
    var copy = new ArrayList<>(events);
    java.util.Collections.reverse(copy);
    return copy.stream()
        .filter(e -> tenantId == null || tenantId.equals(e.tenantId()))
        .limit(limit)
        .toList();
  }

  @Override
  public synchronized java.util.Optional<Anchor> anchor() {
    return events.isEmpty()
        ? java.util.Optional.empty()
        : java.util.Optional.of(
            new Anchor(events.get(events.size() - 1).hash(), events.size(), keyedFromSeq));
  }

  /** Test hook: replaces a row in place to simulate tampering. */
  public synchronized void tamper(int index, AuditEvent replacement) {
    events.set(index, replacement);
  }
}

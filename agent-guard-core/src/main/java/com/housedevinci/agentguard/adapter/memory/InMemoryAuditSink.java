package com.housedevinci.agentguard.adapter.memory;

import com.housedevinci.agentguard.domain.AuditAnchor;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import java.util.ArrayList;
import java.util.List;

/**
 * Append-only, hash-chained, in memory. For tests and development. A trail is keyed from row 1 or
 * unkeyed forever, matching the sink's own {@link AuditChain} for the whole lifetime of the
 * instance (design change, QUESTIONS.md #20: "keyed-from-birth") — there is no persisted state to
 * restart against, so this store has nothing analogous to {@code JdbcAuditSink}'s startup/append
 * key-mismatch check.
 *
 * <p><b>No external anchor (the security review H3):</b> {@link #anchor()} derives {@code headHash}/{@code
 * rowCount} from the last element of {@link #events} and {@code keyed} from this instance's own
 * {@link AuditChain}, i.e. from the very list it claims to anchor. Unlike {@code JdbcAuditSink},
 * whose anchor is a separate, append-only-guarded row, this store cannot detect its own tail being
 * trimmed: a trimmed trail still verifies {@code INTACT}/{@code INTACT_UNKEYED} with {@code
 * anchored() == true}. Not a substitute for the JDBC store in any deployment where the audit trail
 * matters.
 */
public final class InMemoryAuditSink implements AuditSink, AuditReader, AuditAnchor {

  private final List<AuditEvent> events = new ArrayList<>();
  private final AuditChain chain;

  public InMemoryAuditSink() {
    this(AuditChain.unkeyed());
  }

  public InMemoryAuditSink(AuditChain chain) {
    this.chain = chain;
  }

  @Override
  public synchronized AuditEvent append(AuditEvent event) {
    String prev = events.isEmpty() ? AuditChain.GENESIS : events.get(events.size() - 1).hash();
    var linked = chain.linkEvent(event.withSequence(events.size() + 1L), prev);
    events.add(linked);
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
            new Anchor(events.get(events.size() - 1).hash(), events.size(), chain.isKeyed()));
  }

  /** Test hook: replaces a row in place to simulate tampering. */
  public synchronized void tamper(int index, AuditEvent replacement) {
    events.set(index, replacement);
  }
}

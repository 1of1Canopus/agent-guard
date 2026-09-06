package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.AuditAnchor;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Walks the audit trail in sequence order, recomputes every hash and compares the head with the
 * {@link AuditAnchor} when the reader provides one.
 */
public final class AuditChainVerifier {

  private static final int PAGE = 500;

  private final AuditReader reader;
  private final AuditAnchor anchor;

  public AuditChainVerifier(AuditReader reader) {
    this(reader, reader instanceof AuditAnchor a ? a : Optional::empty);
  }

  public AuditChainVerifier(AuditReader reader, AuditAnchor anchor) {
    this.reader = Objects.requireNonNull(reader, "reader");
    this.anchor = Objects.requireNonNull(anchor, "anchor");
  }

  public enum Status {
    /** No rows and no anchor. */
    EMPTY,
    /** Every hash recomputes and the head matches the anchor (or there is no anchor). */
    INTACT,
    /** A row does not recompute from its predecessor: {@code brokenAtSequence} says which. */
    BROKEN,
    /** The rows recompute but the head hash or row count differs from the anchor. */
    ANCHOR_MISMATCH
  }

  /**
   * @param status outcome
   * @param verified number of rows that recomputed
   * @param brokenAtSequence sequence of the first row that fails, or -1
   * @param headHash hash of the newest verified row, or GENESIS
   */
  public record Report(Status status, long verified, long brokenAtSequence, String headHash) {
    public boolean intact() {
      return status == Status.INTACT || status == Status.EMPTY;
    }
  }

  public Report verify() {
    String prev = AuditChain.GENESIS;
    long after = 0;
    long count = 0;
    while (true) {
      List<AuditEvent> page = reader.readAfter(after, PAGE);
      if (page.isEmpty()) {
        break;
      }
      for (AuditEvent e : page) {
        if (!AuditChain.verify(e, prev)) {
          return new Report(Status.BROKEN, count, e.sequence(), prev);
        }
        prev = e.hash();
        after = e.sequence();
        count++;
      }
    }
    Optional<AuditAnchor.Anchor> a = anchor.anchor();
    if (a.isPresent() && (a.get().rowCount() != count || !a.get().headHash().equals(prev))) {
      return new Report(Status.ANCHOR_MISMATCH, count, -1, prev);
    }
    if (count == 0 && a.isEmpty()) {
      return new Report(Status.EMPTY, 0, -1, prev);
    }
    return new Report(Status.INTACT, count, -1, prev);
  }
}

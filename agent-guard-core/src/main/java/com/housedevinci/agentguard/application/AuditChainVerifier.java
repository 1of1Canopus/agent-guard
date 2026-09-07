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
  private final AuditChain chain;

  public AuditChainVerifier(AuditReader reader) {
    this(reader, reader instanceof AuditAnchor a ? a : Optional::empty, AuditChain.unkeyed());
  }

  public AuditChainVerifier(AuditReader reader, AuditAnchor anchor) {
    this(reader, anchor, AuditChain.unkeyed());
  }

  /** With the same (possibly keyed) chain the sink used. */
  public AuditChainVerifier(AuditReader reader, AuditAnchor anchor, AuditChain chain) {
    this.reader = Objects.requireNonNull(reader, "reader");
    this.anchor = Objects.requireNonNull(anchor, "anchor");
    this.chain = Objects.requireNonNull(chain, "chain");
  }

  public static AuditChainVerifier of(AuditReader reader, AuditChain chain) {
    return new AuditChainVerifier(
        reader, reader instanceof AuditAnchor a ? a : Optional::empty, chain);
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
    // V2: chain_version is part of what a table-owning attacker can rewrite, so once a row has
    // verified keyed, no later row may fall back to an unkeyed version and still be trusted — that
    // would let a rewritten, downgraded trail verify INTACT with a key that never touched it.
    boolean keyedSeen = false;
    while (true) {
      List<AuditEvent> page = reader.readAfter(after, PAGE);
      if (page.isEmpty()) {
        break;
      }
      for (AuditEvent e : page) {
        if (keyedSeen && !AuditChain.KEYED_VERSION.equals(e.version())) {
          return new Report(Status.BROKEN, count, e.sequence(), prev);
        }
        if (!chainFor(e).verifyEvent(e, prev)) {
          return new Report(Status.BROKEN, count, e.sequence(), prev);
        }
        if (AuditChain.KEYED_VERSION.equals(e.version())) {
          keyedSeen = true;
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

  /**
   * C6: a row is verified with the chain that actually produced its hash, not with whatever chain
   * is configured today. Rows written before {@code agentguard.audit.hmac-secret} was ever set
   * carry {@link AuditChain#CANONICAL_VERSION} (or no recorded version at all, on installations
   * that predate this column — the schema step backfills it to {@code ag1}) and are always verified
   * unkeyed; rows carrying {@link AuditChain#KEYED_VERSION} are verified with the chain this
   * verifier was constructed with (which must be keyed with the same secret they were written with,
   * or they will not recompute — that is a real break, not a version mismatch).
   */
  private AuditChain chainFor(AuditEvent e) {
    return AuditChain.KEYED_VERSION.equals(e.version()) ? chain : AuditChain.unkeyed();
  }
}

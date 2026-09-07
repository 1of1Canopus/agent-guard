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
    ANCHOR_MISMATCH,
    /**
     * V2 (QUESTIONS.md #20): a key was given, every row recomputes, and the anchor's {@code
     * keyed_from_seq} is {@code null} — no row was ever appended under a keyed chain, i.e. the key
     * is not actually protecting anything in this trail yet. Distinct from {@code INTACT} so an
     * operator who believes {@code agentguard.audit.hmac-secret} is active on this trail sees that
     * it is not, instead of a clean report that looks the same as a genuinely keyed one.
     */
    UNKEYED
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
    // V2 (QUESTIONS.md #20, the maintainers's ruling): a row's own chain_version is not enough — it is part
    // of what a table-owning attacker rewrites, and a whole-trail downgrade to GENESIS/ag1 is then
    // byte-for-byte the same data as a trail that has never used HMAC (the case
    // CipherProbeCleanGuardTest.enabling_the_audit_hmac_secret_does_not_break_the_existing_trail
    // must keep reporting INTACT). The external signal is the anchor's keyed_from_seq: set once, in
    // the same transaction as the first row appended under a keyed chain, and never movable
    // afterwards (the anchor's monotonic trigger, the security review R4) — an attacker who rewrites audit rows
    // cannot also move it.
    Optional<AuditAnchor.Anchor> anchored = anchor.anchor();
    boolean keyGiven = chain.isKeyed();
    Long keyedFromSeq = anchored.map(AuditAnchor.Anchor::keyedFromSeq).orElse(null);
    boolean anchorKnowsKeying = anchored.isPresent();

    String prev = AuditChain.GENESIS;
    long after = 0;
    long count = 0;
    // Fallback for readers that do not implement AuditAnchor (or report no anchor row yet): the
    // in-trail forward-only rule from the previous round. It still catches a *partial* downgrade
    // (a genuine keyed prefix, a downgraded tail) even with no anchor to consult; it cannot catch a
    // whole-trail downgrade, which is exactly why the anchor check above exists.
    boolean keyedSeen = false;
    while (true) {
      List<AuditEvent> page = reader.readAfter(after, PAGE);
      if (page.isEmpty()) {
        break;
      }
      for (AuditEvent e : page) {
        boolean isKeyedVersion = AuditChain.KEYED_VERSION.equals(e.version());
        if (keyGiven && anchorKnowsKeying) {
          boolean expectKeyed = keyedFromSeq != null && e.sequence() >= keyedFromSeq;
          if (keyedFromSeq == null ? isKeyedVersion : expectKeyed != isKeyedVersion) {
            return new Report(Status.BROKEN, count, e.sequence(), prev);
          }
        } else if (keyedSeen && !isKeyedVersion) {
          return new Report(Status.BROKEN, count, e.sequence(), prev);
        }
        if (!chainFor(e).verifyEvent(e, prev)) {
          return new Report(Status.BROKEN, count, e.sequence(), prev);
        }
        if (isKeyedVersion) {
          keyedSeen = true;
        }
        prev = e.hash();
        after = e.sequence();
        count++;
      }
    }
    if (anchored.isPresent()
        && (anchored.get().rowCount() != count || !anchored.get().headHash().equals(prev))) {
      return new Report(Status.ANCHOR_MISMATCH, count, -1, prev);
    }
    if (count == 0 && anchored.isEmpty()) {
      return new Report(Status.EMPTY, 0, -1, prev);
    }
    if (keyGiven && anchorKnowsKeying && keyedFromSeq == null) {
      return new Report(Status.UNKEYED, count, -1, prev);
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

package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.AuditAnchor;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Walks the audit trail in sequence order, recomputes every hash and compares the head with the
 * {@link AuditAnchor} when the reader provides one.
 *
 * <p>Holds a keyring ({@code keyId -> secret}) rather than one key: the key id is part of the
 * hashed material from row 1 (see {@link AuditChain}), so a rotation window has rows signed by
 * different ids in the same, still-keyed trail — the verifier just needs every id that ever signed
 * a row it is asked to check. An id it does not hold is {@code BROKEN}, not skipped.
 */
public final class AuditChainVerifier {

  private static final int PAGE = 500;
  private static final Logger log = LoggerFactory.getLogger(AuditChainVerifier.class);

  private final AuditReader reader;
  private final AuditAnchor anchor;
  private final Map<String, AuditChain> keyring;

  public AuditChainVerifier(AuditReader reader) {
    this(reader, reader instanceof AuditAnchor a ? a : Optional::empty, Map.of());
  }

  public AuditChainVerifier(AuditReader reader, AuditAnchor anchor) {
    this(reader, anchor, Map.of());
  }

  /** With the same (possibly keyed) chain the sink used; back-compat single-key form. */
  public AuditChainVerifier(AuditReader reader, AuditAnchor anchor, AuditChain chain) {
    this.reader = Objects.requireNonNull(reader, "reader");
    this.anchor = Objects.requireNonNull(anchor, "anchor");
    this.keyring = chain.isKeyed() ? Map.of(chain.keyId(), chain) : Map.of();
  }

  /**
   * With a keyring covering every key id that may have signed a row in this trail (secret bytes, at
   * least {@link AuditChain#MIN_KEY_BYTES} each).
   */
  public AuditChainVerifier(AuditReader reader, AuditAnchor anchor, Map<String, byte[]> keyring) {
    this.reader = Objects.requireNonNull(reader, "reader");
    this.anchor = Objects.requireNonNull(anchor, "anchor");
    Objects.requireNonNull(keyring, "keyring");
    var chains = new LinkedHashMap<String, AuditChain>();
    keyring.forEach((id, secret) -> chains.put(id, AuditChain.keyed(secret, id)));
    this.keyring = Map.copyOf(chains);
  }

  public static AuditChainVerifier of(AuditReader reader, AuditChain chain) {
    return new AuditChainVerifier(
        reader, reader instanceof AuditAnchor a ? a : Optional::empty, chain);
  }

  public static AuditChainVerifier of(AuditReader reader, Map<String, byte[]> keyring) {
    return new AuditChainVerifier(
        reader, reader instanceof AuditAnchor a ? a : Optional::empty, keyring);
  }

  public enum Status {
    /** No rows and no anchor. */
    EMPTY,
    /** Every hash recomputes and the head matches the anchor; the trail is keyed. */
    INTACT,
    /**
     * Every hash recomputes and the head matches the anchor; the trail is unkeyed. Rendered with a
     * distinct word from {@link #INTACT} on purpose: an unkeyed trail's integrity rests only on
     * database privilege separation, not on a secret, and must never look the same as a keyed
     * trail's clean result.
     */
    INTACT_UNKEYED,
    /**
     * A row does not recompute from its predecessor, claims the wrong chain version, or claims a
     * key id the verifier's keyring does not hold.
     */
    BROKEN,
    /** The rows recompute but the head hash or row count differs from the anchor. */
    ANCHOR_MISMATCH,
    /**
     * The reader is not an {@link AuditAnchor}, or has no anchor row, and the trail is not empty.
     * Reported unconditionally — keyed or unkeyed — never as {@code INTACT}/{@code INTACT_UNKEYED}:
     * without the anchor there is no attacker-unwritable record of what this trail's rows ought to
     * claim, so the verifier refuses to guess.
     */
    NO_ANCHOR
  }

  /**
   * @param status outcome
   * @param verified number of rows that recomputed
   * @param brokenAtSequence sequence of the first row that fails, or -1
   * @param headHash hash of the newest verified row, or GENESIS
   * @param anchored whether an anchor row was available for this verification
   * @param keyed the trail's recorded mode (from the anchor), or {@code false} when {@code
   *     !anchored}
   * @param keyIds every distinct key id seen on a row that recomputed successfully
   */
  public record Report(
      Status status,
      long verified,
      long brokenAtSequence,
      String headHash,
      boolean anchored,
      boolean keyed,
      Set<String> keyIds) {
    public boolean intact() {
      return status == Status.INTACT || status == Status.INTACT_UNKEYED || status == Status.EMPTY;
    }
  }

  public Report verify() {
    // Keyed-from-birth (QUESTIONS.md #20): a trail is keyed from row 1 or unkeyed forever, recorded
    // once on the anchor's `keyed` flag and immutable afterwards (the anchor's monotonic trigger).
    // A reader with no anchor available is never rendered INTACT/INTACT_UNKEYED, keyed or not: the
    // anchor is the only attacker-unwritable record of what every row's chain_version/key_id ought
    // to be.
    Optional<AuditAnchor.Anchor> anchored = anchor.anchor();
    if (anchored.isEmpty()) {
      List<AuditEvent> probe = reader.readAfter(0, 1);
      if (probe.isEmpty()) {
        return new Report(Status.EMPTY, 0, -1, AuditChain.GENESIS, false, false, Set.of());
      }
      log.warn(
          "agentguard: verifying a non-empty trail without an anchor (the reader is not an"
              + " AuditAnchor, or the anchor row is missing); refusing to report INTACT. Reporting"
              + " NO_ANCHOR.");
      return new Report(Status.NO_ANCHOR, 0, -1, AuditChain.GENESIS, false, false, Set.of());
    }
    boolean expectKeyed = anchored.get().keyed();
    String expectedVersion = expectKeyed ? AuditChain.KEYED_VERSION : AuditChain.CANONICAL_VERSION;

    String prev = AuditChain.GENESIS;
    long after = 0;
    long count = 0;
    Set<String> keyIdsSeen = new LinkedHashSet<>();
    while (true) {
      List<AuditEvent> page = reader.readAfter(after, PAGE);
      if (page.isEmpty()) {
        break;
      }
      for (AuditEvent e : page) {
        if (!expectedVersion.equals(e.version())) {
          return new Report(
              Status.BROKEN, count, e.sequence(), prev, true, expectKeyed, keyIdsSeen);
        }
        AuditChain rowChain = chainForRow(expectKeyed, e.keyId());
        if (rowChain == null || !rowChain.verifyEvent(e, prev)) {
          return new Report(
              Status.BROKEN, count, e.sequence(), prev, true, expectKeyed, keyIdsSeen);
        }
        keyIdsSeen.add(e.keyId());
        prev = e.hash();
        after = e.sequence();
        count++;
      }
    }
    if (anchored.get().rowCount() != count || !anchored.get().headHash().equals(prev)) {
      return new Report(Status.ANCHOR_MISMATCH, count, -1, prev, true, expectKeyed, keyIdsSeen);
    }
    if (count == 0) {
      return new Report(Status.EMPTY, 0, -1, prev, true, expectKeyed, keyIdsSeen);
    }
    return new Report(
        expectKeyed ? Status.INTACT : Status.INTACT_UNKEYED,
        count,
        -1,
        prev,
        true,
        expectKeyed,
        keyIdsSeen);
  }

  /**
   * The {@link AuditChain} to recompute one row with, or {@code null} if the row's claimed key id
   * cannot be verified at all (unknown to the keyring, or a key id used on the wrong trail mode).
   * An attacker with table-write access can relabel a row's {@code key_id} to one already in this
   * keyring, but cannot also produce a matching hash without that id's secret — the id is baked
   * into the hashed material itself (see {@link AuditChain}), so this is not a second mode switch,
   * only a question of which already-trusted key signed which row.
   */
  private AuditChain chainForRow(boolean expectKeyed, String rowKeyId) {
    if (!expectKeyed) {
      return AuditChain.UNKEYED_KEY_ID.equals(rowKeyId) ? AuditChain.unkeyed() : null;
    }
    if (AuditChain.UNKEYED_KEY_ID.equals(rowKeyId)) {
      return null; // a keyed trail's row must carry a real key id
    }
    return keyring.get(rowKeyId);
  }
}

package com.housedevinci.agentguard.domain;

import java.util.Optional;

/**
 * The chain head as the sink last wrote it: the hash of the newest row and the row count. Kept in a
 * separate row (table) from the trail so that trimming the tail or truncating the table leaves a
 * mismatch the verifier reports.
 */
public interface AuditAnchor {

  /**
   * @param headHash hash of the newest row in the trail
   * @param rowCount number of rows in the trail
   * @param keyedFromSeq {@code null} until the first row is appended under a keyed chain; from then
   *     on, the sequence of that row. Set once, in the same transaction as the append that first
   *     used a keyed chain, and immutable afterwards (the anchor's monotonic trigger, the security review R4,
   *     refuses to change it once non-null). This is the external, attacker-unwritable signal
   *     {@link com.housedevinci.agentguard.application.AuditChainVerifier} uses to tell a
   *     legitimately-unkeyed prefix apart from a downgraded one (the security review V2 / QUESTIONS.md #20): the
   *     version a row claims for itself is not enough, because that column is part of what a
   *     table-owning attacker rewrites.
   */
  record Anchor(String headHash, long rowCount, Long keyedFromSeq) {}

  Optional<Anchor> anchor();
}

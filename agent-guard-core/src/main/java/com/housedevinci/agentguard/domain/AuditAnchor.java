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
   * @param keyed whether this trail is keyed (every row uses {@link
   *     com.housedevinci.agentguard.domain.AuditChain#KEYED_VERSION}) or unkeyed (every row uses
   *     {@link com.housedevinci.agentguard.domain.AuditChain#CANONICAL_VERSION}) — set once, at the
   *     first append, and immutable afterwards (the anchor's monotonic trigger, the security review R4, refuses
   *     to change it once set). A trail is keyed from row 1 or unkeyed forever; there is no mixing
   *     and no later switch (design change, QUESTIONS.md #20: "keyed-from-birth"). This is the
   *     external, attacker-unwritable signal {@link
   *     com.housedevinci.agentguard.application.AuditChainVerifier} uses to tell what every row's
   *     {@code chain_version} ought to be, because that column is part of what a table-owning
   *     attacker rewrites and is not itself trustworthy.
   */
  record Anchor(String headHash, long rowCount, boolean keyed) {}

  Optional<Anchor> anchor();
}

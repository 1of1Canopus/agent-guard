package com.housedevinci.agentguard.domain;

import java.util.Optional;

/**
 * The chain head as the sink last wrote it: the hash of the newest row and the row count. Kept in a
 * separate row (table) from the trail so that trimming the tail or truncating the table leaves a
 * mismatch the verifier reports.
 */
public interface AuditAnchor {

  record Anchor(String headHash, long rowCount) {}

  Optional<Anchor> anchor();
}

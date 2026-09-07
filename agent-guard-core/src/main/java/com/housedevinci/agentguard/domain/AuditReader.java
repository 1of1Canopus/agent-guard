package com.housedevinci.agentguard.domain;

import java.util.List;

/** Read side of the audit trail, in sequence order. */
public interface AuditReader {

  /** Events with {@code sequence > afterSequence}, ascending, at most {@code limit}. */
  List<AuditEvent> readAfter(long afterSequence, int limit);

  /**
   * Newest events first, at most {@code limit}, every tenant. Prefer {@link #latest(String, int)}
   * for a tenant-scoped caller: filtering after this applies {@code limit} can hide a tenant's own
   * rows behind a busier neighbour's (Cipher C10).
   */
  default List<AuditEvent> latest(int limit) {
    return latest(null, limit);
  }

  /**
   * Newest events first, at most {@code limit}, restricted to one tenant ({@code null} = every
   * tenant). The filter must apply before {@code limit}, not after (C10).
   */
  List<AuditEvent> latest(String tenantId, int limit);
}

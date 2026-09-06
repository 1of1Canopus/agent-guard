package com.housedevinci.agentguard.domain;

import java.util.List;

/** Read side of the audit trail, in sequence order. */
public interface AuditReader {

  /** Events with {@code sequence > afterSequence}, ascending, at most {@code limit}. */
  List<AuditEvent> readAfter(long afterSequence, int limit);

  /** Newest events first, at most {@code limit}. */
  List<AuditEvent> latest(int limit);
}

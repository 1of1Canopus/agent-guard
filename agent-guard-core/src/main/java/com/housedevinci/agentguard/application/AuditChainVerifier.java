package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import java.util.List;
import java.util.Objects;

/** Walks the audit trail in sequence order and recomputes every hash. */
public final class AuditChainVerifier {

  private static final int PAGE = 500;

  private final AuditReader reader;

  public AuditChainVerifier(AuditReader reader) {
    this.reader = Objects.requireNonNull(reader, "reader");
  }

  /**
   * @param verified number of rows checked
   * @param brokenAtSequence sequence of the first row that fails, or -1 if intact
   */
  public record Report(long verified, long brokenAtSequence) {
    public boolean intact() {
      return brokenAtSequence < 0;
    }
  }

  public Report verify() {
    String prev = AuditChain.GENESIS;
    long after = 0;
    long count = 0;
    while (true) {
      List<AuditEvent> page = reader.readAfter(after, PAGE);
      if (page.isEmpty()) {
        return new Report(count, -1);
      }
      for (AuditEvent e : page) {
        if (!AuditChain.verify(e, prev)) {
          return new Report(count, e.sequence());
        }
        prev = e.hash();
        after = e.sequence();
        count++;
      }
    }
  }
}

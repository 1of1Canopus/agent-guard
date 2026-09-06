package com.housedevinci.agentguard.domain;

/**
 * Hash chain over {@link AuditEvent}s: {@code hash = SHA-256(canonical(event) || prevHash)}. The
 * first row links to {@link #GENESIS}. A verifier walks the rows in sequence order and recomputes.
 */
public final class AuditChain {

  public static final String GENESIS = "0".repeat(64);

  private AuditChain() {}

  public static String canonical(AuditEvent e) {
    return String.join(
        "|",
        e.timestamp().toString(),
        e.principalId(),
        nullToEmpty(e.tenantId()),
        e.tool(),
        e.argsHash(),
        e.resultHash(),
        Long.toString(e.latencyMillis()),
        e.decision().name(),
        e.correlationId(),
        nullToEmpty(e.decisionId()));
  }

  public static String hashOf(AuditEvent e, String prevHash) {
    return Hashes.sha256Hex(canonical(e) + "|" + prevHash);
  }

  /** Returns the event with {@code prevHash} and {@code hash} filled in. */
  public static AuditEvent link(AuditEvent e, String prevHash) {
    return e.withChain(prevHash, hashOf(e, prevHash));
  }

  /** True if the event's stored hash matches a recomputation from {@code expectedPrev}. */
  public static boolean verify(AuditEvent e, String expectedPrev) {
    return expectedPrev.equals(e.prevHash()) && hashOf(e, expectedPrev).equals(e.hash());
  }

  private static String nullToEmpty(String s) {
    return s == null ? "" : s;
  }
}

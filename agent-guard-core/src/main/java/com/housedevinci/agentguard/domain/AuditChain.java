package com.housedevinci.agentguard.domain;

import java.nio.charset.StandardCharsets;

/**
 * Hash chain over {@link AuditEvent}s: {@code hash = SHA-256(canonical(event) || prevHash)}. The
 * canonical form is length-prefixed ({@code <byteLength>:<value>} per field, null as {@code -}), so
 * no rewrite can move a boundary between two fields without changing the hash. The first row links
 * to {@link #GENESIS}. A verifier walks the rows in sequence order and recomputes.
 */
public final class AuditChain {

  public static final String GENESIS = "0".repeat(64);

  /** Bumped whenever the canonical form changes; part of the hashed material. */
  public static final String CANONICAL_VERSION = "ag1";

  private AuditChain() {}

  public static String canonical(AuditEvent e) {
    var sb = new StringBuilder(CANONICAL_VERSION);
    field(sb, e.timestamp().toString());
    field(sb, e.principalId());
    field(sb, e.tenantId());
    field(sb, e.tool());
    field(sb, e.argsHash());
    field(sb, e.resultHash());
    field(sb, Long.toString(e.latencyMillis()));
    field(sb, e.decision().name());
    field(sb, e.correlationId());
    field(sb, e.decisionId());
    field(sb, e.actorId());
    return sb.toString();
  }

  private static void field(StringBuilder sb, String value) {
    sb.append('|');
    if (value == null) {
      sb.append('-');
      return;
    }
    sb.append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value);
  }

  public static String hashOf(AuditEvent e, String prevHash) {
    return Hashes.sha256Hex(canonical(e) + "|" + prevHash.length() + ":" + prevHash);
  }

  /** Returns the event with {@code prevHash} and {@code hash} filled in. */
  public static AuditEvent link(AuditEvent e, String prevHash) {
    return e.withChain(prevHash, hashOf(e, prevHash));
  }

  /** True if the event's stored hash matches a recomputation from {@code expectedPrev}. */
  public static boolean verify(AuditEvent e, String expectedPrev) {
    return expectedPrev.equals(e.prevHash()) && hashOf(e, expectedPrev).equals(e.hash());
  }
}

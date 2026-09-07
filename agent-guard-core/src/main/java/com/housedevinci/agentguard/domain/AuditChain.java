package com.housedevinci.agentguard.domain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hash chain over {@link AuditEvent}s: {@code hash = H(canonical(event) || prevHash)} where {@code
 * H} is SHA-256 ({@link #unkeyed()}, version {@code ag1}) or HMAC-SHA256 with a secret ({@link
 * #keyed(byte[])}, version {@code ag2h}: anyone without the key can extend the chain but not
 * rewrite it consistently). The canonical form is length-prefixed ({@code <byteLength>:<value>} per
 * field, null as {@code -}), so no rewrite can move a boundary between two fields without changing
 * the hash. The first row links to {@link #GENESIS}.
 */
public final class AuditChain {

  public static final String GENESIS = "0".repeat(64);
  public static final String CANONICAL_VERSION = "ag1";
  public static final String KEYED_VERSION = "ag2h";
  public static final int MIN_KEY_BYTES = 32;

  private static final AuditChain UNKEYED = new AuditChain(null);

  private final byte[] key;

  private AuditChain(byte[] key) {
    this.key = key;
  }

  public static AuditChain unkeyed() {
    return UNKEYED;
  }

  public static AuditChain keyed(byte[] secret) {
    Objects.requireNonNull(secret, "secret");
    if (secret.length < MIN_KEY_BYTES) {
      throw new IllegalArgumentException(
          "audit HMAC secret must be at least " + MIN_KEY_BYTES + " bytes");
    }
    return new AuditChain(secret.clone());
  }

  public boolean isKeyed() {
    return key != null;
  }

  public String version() {
    return isKeyed() ? KEYED_VERSION : CANONICAL_VERSION;
  }

  public static String canonical(AuditEvent e) {
    return canonical(e, CANONICAL_VERSION);
  }

  private static String canonical(AuditEvent e, String version) {
    var sb = new StringBuilder(version);
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

  public String hashOfEvent(AuditEvent e, String prevHash) {
    String material = canonical(e, version()) + "|" + prevHash.length() + ":" + prevHash;
    if (key == null) {
      return Hashes.sha256Hex(material);
    }
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return HexFormat.of().formatHex(mac.doFinal(material.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("HmacSHA256 not available", ex);
    }
  }

  /** Returns the event with {@code version}, {@code prevHash} and {@code hash} filled in. */
  public AuditEvent linkEvent(AuditEvent e, String prevHash) {
    return e.withChain(prevHash, version(), hashOfEvent(e, prevHash));
  }

  /** True if the event's stored hash matches a recomputation from {@code expectedPrev}. */
  public boolean verifyEvent(AuditEvent e, String expectedPrev) {
    return expectedPrev.equals(e.prevHash()) && hashOfEvent(e, expectedPrev).equals(e.hash());
  }

  // ---- unkeyed static shortcuts (kept for callers of the first release) ----

  public static String hashOf(AuditEvent e, String prevHash) {
    return UNKEYED.hashOfEvent(e, prevHash);
  }

  public static AuditEvent link(AuditEvent e, String prevHash) {
    return UNKEYED.linkEvent(e, prevHash);
  }

  public static boolean verify(AuditEvent e, String expectedPrev) {
    return UNKEYED.verifyEvent(e, expectedPrev);
  }
}

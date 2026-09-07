package com.housedevinci.agentguard.domain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hash chain over {@link AuditEvent}s: {@code hash = H(canonical(event, keyId) || prevHash)} where
 * {@code H} is SHA-256 ({@link #unkeyed()}, version {@code ag1}, key id {@link #UNKEYED_KEY_ID}) or
 * HMAC-SHA256 with a secret ({@link #keyed(byte[], String)}, version {@code ag2h}: anyone without
 * the key can extend the chain but not rewrite it consistently). The canonical form is
 * length-prefixed ({@code <byteLength>:<value>} per field, null as {@code -}), so no rewrite can
 * move a boundary between two fields without changing the hash. The first row links to {@link
 * #GENESIS}.
 *
 * <p>The key id is part of the hashed material, from row 1, so key rotation is data, not a format
 * break: a trail's keyed-or-not state (recorded once on the anchor, immutable — see {@link
 * com.housedevinci.agentguard.domain.AuditAnchor}) never changes, but which specific key wrote a
 * given row can, across a rotation. An attacker who owns write access can relabel a row's {@code
 * key_id} only to an id whose secret they also hold — relabelling to a key already in the
 * verifier's keyring without knowing its secret still fails to recompute the hash, because the id
 * is baked into the material the secret signs. This is not a second mode switch; it is who signed a
 * given row within one mode.
 */
public final class AuditChain {

  public static final String GENESIS = "0".repeat(64);
  public static final String CANONICAL_VERSION = "ag1";
  public static final String KEYED_VERSION = "ag2h";
  public static final String UNKEYED_KEY_ID = "none";
  public static final int MIN_KEY_BYTES = 32;

  private static final AuditChain UNKEYED = new AuditChain(null, UNKEYED_KEY_ID);

  private final byte[] key;
  private final String keyId;

  private AuditChain(byte[] key, String keyId) {
    this.key = key;
    this.keyId = Objects.requireNonNull(keyId, "keyId");
  }

  public static AuditChain unkeyed() {
    return UNKEYED;
  }

  /** Keyed with the default key id {@code k1}; kept for callers that do not rotate keys. */
  public static AuditChain keyed(byte[] secret) {
    return keyed(secret, "k1");
  }

  public static AuditChain keyed(byte[] secret, String keyId) {
    Objects.requireNonNull(secret, "secret");
    Objects.requireNonNull(keyId, "keyId");
    if (secret.length < MIN_KEY_BYTES) {
      throw new IllegalArgumentException(
          "audit HMAC secret must be at least " + MIN_KEY_BYTES + " bytes");
    }
    if (keyId.isBlank() || UNKEYED_KEY_ID.equals(keyId)) {
      throw new IllegalArgumentException(
          "audit HMAC key id must not be blank or '" + UNKEYED_KEY_ID + "' (reserved for unkeyed)");
    }
    return new AuditChain(secret.clone(), keyId);
  }

  public boolean isKeyed() {
    return key != null;
  }

  public String keyId() {
    return keyId;
  }

  public String version() {
    return isKeyed() ? KEYED_VERSION : CANONICAL_VERSION;
  }

  public static String canonical(AuditEvent e) {
    return canonical(e, CANONICAL_VERSION, UNKEYED_KEY_ID);
  }

  private static String canonical(AuditEvent e, String version, String keyId) {
    var sb = new StringBuilder(version);
    field(sb, keyId);
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
    String material = canonical(e, version(), keyId) + "|" + prevHash.length() + ":" + prevHash;
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

  /**
   * Returns the event with {@code version}, {@code keyId}, {@code prevHash} and {@code hash} filled
   * in.
   */
  public AuditEvent linkEvent(AuditEvent e, String prevHash) {
    return e.withChain(prevHash, version(), keyId, hashOfEvent(e, prevHash));
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

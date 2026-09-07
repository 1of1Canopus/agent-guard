package com.housedevinci.agentguard.domain;

/**
 * The form of the arguments that is hashed and bound to a decision: compact JSON with sorted object
 * keys, so whitespace and key order do not create a second decision for the same call. Text that is
 * not JSON is hashed as is.
 */
public final class ArgumentCanonicalizer {
  private ArgumentCanonicalizer() {}

  public static String canonical(String argumentsJson) {
    if (argumentsJson == null) {
      return "";
    }
    return JsonText.parse(argumentsJson).map(n -> n.toJson(true)).orElse(argumentsJson);
  }

  /**
   * V3: domain-separated from {@link com.housedevinci.agentguard.application.AuditRecorder
   * #recordOversized}'s raw-text hash, so a denied oversized call can never share {@code args_hash}
   * with an allowed one. Canonicalisation is not size-preserving (an unpaired surrogate goes from
   * one raw UTF-8 byte to a six-byte {@code \\u} escape), so a payload under the byte cap can still
   * produce a canonical form over it.
   */
  static final String CANONICAL_HASH_DOMAIN = "agcanon1:"; // package-visible for tests

  public static String hash(String argumentsJson) {
    return Hashes.sha256Hex(CANONICAL_HASH_DOMAIN + canonical(argumentsJson));
  }
}

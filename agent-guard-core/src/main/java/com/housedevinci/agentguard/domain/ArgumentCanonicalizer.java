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

  public static String hash(String argumentsJson) {
    return Hashes.sha256Hex(canonical(argumentsJson));
  }
}

package com.housedevinci.agentguard.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 helpers. */
public final class Hashes {
  private Hashes() {}

  public static String sha256Hex(String text) {
    try {
      var digest = MessageDigest.getInstance("SHA-256");
      var bytes = digest.digest((text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }
}

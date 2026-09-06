package com.housedevinci.agentguard.domain;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Produces the human-visible preview of tool arguments: values of sensitive keys are masked,
 * bearer-like tokens are masked wherever they appear, control characters are stripped (log
 * injection) and the result is length-capped.
 */
public final class ArgumentRedactor {

  public static final String MASK = "***";
  public static final String TRUNCATION_MARK = "...[truncated]";
  public static final int DEFAULT_MAX_LENGTH = 512;

  public static final Set<String> DEFAULT_SENSITIVE_KEYS =
      Set.of(
          "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token",
          "api_key", "apikey", "authorization", "auth", "credential", "credentials", "private_key",
          "ssn", "iban", "card_number", "credit_card", "cvv", "pin");

  private static final Pattern CONTROL = Pattern.compile("[\\p{Cntrl}\\u2028\\u2029]");
  private static final Pattern BEARER =
      Pattern.compile("(?i)(bearer\\s+)[A-Za-z0-9\\-._~+/]+=*");

  private final Set<String> sensitiveKeys;
  private final int maxLength;
  private final Pattern keyValue;

  public ArgumentRedactor(Set<String> sensitiveKeys, int maxLength) {
    Objects.requireNonNull(sensitiveKeys, "sensitiveKeys");
    if (maxLength < 16) {
      throw new IllegalArgumentException("maxLength must be >= 16");
    }
    this.sensitiveKeys =
        sensitiveKeys.stream().map(k -> k.toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toUnmodifiableSet());
    this.maxLength = maxLength;
    // "key" : <string | number | true | false | null>
    this.keyValue =
        Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"(?:\\\\.|[^\"\\\\])*\"|-?\\d+(?:\\.\\d+)?|true|false|null)");
  }

  public static ArgumentRedactor defaults() {
    return new ArgumentRedactor(DEFAULT_SENSITIVE_KEYS, DEFAULT_MAX_LENGTH);
  }

  public String preview(String argumentsJson) {
    if (argumentsJson == null || argumentsJson.isEmpty()) {
      return "";
    }
    String masked = maskKeys(argumentsJson);
    masked = BEARER.matcher(masked).replaceAll("$1" + MASK);
    masked = CONTROL.matcher(masked).replaceAll("");
    if (masked.length() > maxLength) {
      return masked.substring(0, maxLength) + TRUNCATION_MARK;
    }
    return masked;
  }

  private String maskKeys(String json) {
    Matcher m = keyValue.matcher(json);
    var sb = new StringBuilder(json.length());
    while (m.find()) {
      String key = m.group(1);
      if (isSensitive(key)) {
        m.appendReplacement(sb, Matcher.quoteReplacement("\"" + key + "\":\"" + MASK + "\""));
      } else {
        m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
      }
    }
    m.appendTail(sb);
    return sb.toString();
  }

  private boolean isSensitive(String key) {
    var lower = key.toLowerCase(Locale.ROOT);
    if (sensitiveKeys.contains(lower)) {
      return true;
    }
    return sensitiveKeys.stream().anyMatch(s -> lower.endsWith("_" + s) || lower.endsWith(s) && lower.length() > s.length() && !Character.isLetter(lower.charAt(lower.length() - s.length() - 1)));
  }
}

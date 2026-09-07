package com.housedevinci.agentguard.domain;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Produces the human-visible form of tool arguments by walking the parsed JSON: the whole value of
 * a sensitive key is masked whatever its shape (string, number, array, object); keys are compared
 * after JSON unescaping; bearer-like tokens are masked inside any string; control and format
 * characters are stripped (log injection); unparseable input is fully masked. {@link #preview}
 * additionally caps the length.
 */
public final class ArgumentRedactor {

  public static final String MASK = "***";
  public static final String TRUNCATION_MARK = "...[truncated]";
  public static final int DEFAULT_MAX_LENGTH = 512;

  public static final Set<String> DEFAULT_SENSITIVE_KEYS =
      Set.of(
          "password",
          "passwd",
          "pwd",
          "secret",
          "token",
          "access_token",
          "refresh_token",
          "api_key",
          "apikey",
          "authorization",
          "auth",
          "credential",
          "credentials",
          "private_key",
          "ssn",
          "iban",
          "card_number",
          "credit_card",
          "cvv",
          "pin");

  private static final Pattern CONTROL = Pattern.compile("[\\p{Cc}\\p{Cf}\\u0085\\u2028\\u2029]");
  private static final Pattern BEARER = Pattern.compile("(?i)(bearer\\s+)[A-Za-z0-9\\-._~+/]+=*");

  private final Set<String> sensitiveKeys;
  private final int maxLength;

  public ArgumentRedactor(Set<String> sensitiveKeys, int maxLength) {
    Objects.requireNonNull(sensitiveKeys, "sensitiveKeys");
    if (maxLength < 16) {
      throw new IllegalArgumentException("maxLength must be >= 16");
    }
    this.sensitiveKeys =
        sensitiveKeys.stream()
            .map(k -> k.toLowerCase(Locale.ROOT))
            .collect(Collectors.toUnmodifiableSet());
    this.maxLength = maxLength;
  }

  public static ArgumentRedactor defaults() {
    return new ArgumentRedactor(DEFAULT_SENSITIVE_KEYS, DEFAULT_MAX_LENGTH);
  }

  /** Redacted and length-capped: what logs, notifiers and list views show. */
  public String preview(String argumentsJson) {
    String masked = redact(argumentsJson);
    if (masked.length() > maxLength) {
      return masked.substring(0, maxLength) + TRUNCATION_MARK;
    }
    return masked;
  }

  /** Redacted but complete: what an approver reads before attesting the arguments hash. */
  public String redact(String argumentsJson) {
    if (argumentsJson == null || argumentsJson.isEmpty()) {
      return "";
    }
    String masked =
        JsonText.parse(argumentsJson).map(n -> mask(n).toJson(false)).orElse("\"" + MASK + "\"");
    return CONTROL.matcher(masked).replaceAll("");
  }

  private JsonNode mask(JsonNode n) {
    return switch (n) {
      case JsonNode.JsonObject o -> {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        o.fields()
            .forEach(
                (k, v) -> out.put(k, isSensitive(k) ? new JsonNode.JsonString(MASK) : mask(v)));
        yield new JsonNode.JsonObject(out);
      }
      case JsonNode.JsonArray a ->
          new JsonNode.JsonArray(a.items().stream().map(this::mask).toList());
      case JsonNode.JsonString s ->
          new JsonNode.JsonString(BEARER.matcher(s.value()).replaceAll("$1" + MASK));
      default -> n;
    };
  }

  private static final Pattern WORD_BOUNDARY =
      Pattern.compile("[_\\-.]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])");

  private boolean isSensitive(String key) {
    var lower = key.toLowerCase(Locale.ROOT);
    if (sensitiveKeys.contains(lower)) {
      return true;
    }
    for (String s : sensitiveKeys) {
      if (lower.endsWith("_" + s) || lower.endsWith("-" + s) || lower.endsWith("." + s)) {
        return true;
      }
      if (lower.endsWith(s)
          && lower.length() > s.length()
          && !Character.isLetter(lower.charAt(lower.length() - s.length() - 1))) {
        return true;
      }
    }
    // split on separators and camel-case boundaries: catches compound spellings the whole-word
    // suffix rule above misses (userPassword, myApiKey, password_confirmation, token_value)
    String[] parts = WORD_BOUNDARY.split(key);
    for (String part : parts) {
      String p = part.toLowerCase(Locale.ROOT);
      if (p.isEmpty()) {
        continue;
      }
      if (sensitiveKeys.contains(p)) {
        return true;
      }
    }
    for (int idx = 0; idx < parts.length - 1; idx++) {
      String joined = (parts[idx] + parts[idx + 1]).toLowerCase(Locale.ROOT);
      if (sensitiveKeys.contains(joined)) {
        return true;
      }
    }
    return false;
  }

  /** Test hook. */
  List<String> keys() {
    return sensitiveKeys.stream().sorted().toList();
  }
}

package com.housedevinci.agentguard.domain;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Strict, dependency-free JSON parser producing {@link JsonNode}; and the string escaper. */
public final class JsonText {

  private final String s;
  private int i;

  private JsonText(String s) {
    this.s = s;
  }

  /** Empty when the text is not a single valid JSON value. */
  public static Optional<JsonNode> parse(String text) {
    if (text == null) {
      return Optional.empty();
    }
    try {
      var p = new JsonText(text);
      p.ws();
      JsonNode v = p.value(0);
      p.ws();
      return p.i == text.length() ? Optional.of(v) : Optional.empty();
    } catch (RuntimeException e) {
      return Optional.empty();
    }
  }

  public static String escape(String v) {
    var sb = new StringBuilder(v.length() + 8);
    for (int k = 0; k < v.length(); k++) {
      char c = v.charAt(k);
      switch (c) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        case '\b' -> sb.append("\\b");
        case '\f' -> sb.append("\\f");
        default -> {
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else if (isUnpairedSurrogate(v, k)) {
            // an unpaired surrogate has no valid UTF-8/UTF-16 partner: leaving it as-is lets
            // String.getBytes(UTF_8) collapse it to a question mark, colliding the canonical hash
            // with a literal question mark in the same position (C1). Escape it as a unicode
            // sequence instead, which is unambiguous and round-trips through the parser's own
            // string-escape handling.
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
        }
      }
    }
    return sb.toString();
  }

  private static boolean isUnpairedSurrogate(String v, int k) {
    char c = v.charAt(k);
    if (Character.isHighSurrogate(c)) {
      return k + 1 >= v.length() || !Character.isLowSurrogate(v.charAt(k + 1));
    }
    if (Character.isLowSurrogate(c)) {
      return k == 0 || !Character.isHighSurrogate(v.charAt(k - 1));
    }
    return false;
  }

  private JsonNode value(int depth) {
    if (depth > 64) {
      throw new IllegalArgumentException("too deep");
    }
    char c = peek();
    return switch (c) {
      case '{' -> object(depth);
      case '[' -> array(depth);
      case '"' -> new JsonNode.JsonString(string());
      case 't' -> literal("true", new JsonNode.JsonBoolean(true));
      case 'f' -> literal("false", new JsonNode.JsonBoolean(false));
      case 'n' -> literal("null", new JsonNode.JsonNull());
      default -> number();
    };
  }

  private JsonNode object(int depth) {
    expect('{');
    Map<String, JsonNode> fields = new LinkedHashMap<>();
    ws();
    if (peek() == '}') {
      i++;
      return new JsonNode.JsonObject(fields);
    }
    while (true) {
      ws();
      String key = string();
      ws();
      expect(':');
      ws();
      fields.put(key, value(depth + 1));
      ws();
      char c = next();
      if (c == '}') {
        return new JsonNode.JsonObject(fields);
      }
      if (c != ',') {
        throw new IllegalArgumentException("expected , or }");
      }
    }
  }

  private JsonNode array(int depth) {
    expect('[');
    List<JsonNode> items = new ArrayList<>();
    ws();
    if (peek() == ']') {
      i++;
      return new JsonNode.JsonArray(items);
    }
    while (true) {
      ws();
      items.add(value(depth + 1));
      ws();
      char c = next();
      if (c == ']') {
        return new JsonNode.JsonArray(items);
      }
      if (c != ',') {
        throw new IllegalArgumentException("expected , or ]");
      }
    }
  }

  private String string() {
    expect('"');
    var sb = new StringBuilder();
    while (true) {
      char c = next();
      if (c == '"') {
        return sb.toString();
      }
      if (c == '\\') {
        char e = next();
        switch (e) {
          case '"' -> sb.append('"');
          case '\\' -> sb.append('\\');
          case '/' -> sb.append('/');
          case 'b' -> sb.append('\b');
          case 'f' -> sb.append('\f');
          case 'n' -> sb.append('\n');
          case 'r' -> sb.append('\r');
          case 't' -> sb.append('\t');
          case 'u' -> {
            if (i + 4 > s.length()) {
              throw new IllegalArgumentException("bad \\u escape");
            }
            String hex = s.substring(i, i + 4);
            for (int h = 0; h < 4; h++) {
              if (!isHexDigit(hex.charAt(h))) {
                throw new IllegalArgumentException("bad \\u escape");
              }
            }
            sb.append((char) Integer.parseInt(hex, 16));
            i += 4;
          }
          default -> throw new IllegalArgumentException("bad escape");
        }
      } else if (c < 0x20) {
        throw new IllegalArgumentException("control character in string");
      } else {
        sb.append(c);
      }
    }
  }

  private JsonNode number() {
    int start = i;
    if (peek() == '-') {
      i++;
    }
    digits();
    if (i < s.length() && s.charAt(i) == '.') {
      i++;
      digits();
    }
    if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
      i++;
      if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) {
        i++;
      }
      digits();
    }
    String text = s.substring(start, i);
    if (text.isEmpty() || text.equals("-")) {
      throw new IllegalArgumentException("bad number");
    }
    return new JsonNode.JsonNumber(text);
  }

  private void digits() {
    int start = i;
    while (i < s.length() && isAsciiDigit(s.charAt(i))) {
      i++;
    }
    if (i == start) {
      throw new IllegalArgumentException("digit expected");
    }
  }

  private static boolean isAsciiDigit(char c) {
    return c >= '0' && c <= '9';
  }

  private static boolean isHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  private JsonNode literal(String word, JsonNode node) {
    if (!s.startsWith(word, i)) {
      throw new IllegalArgumentException("bad literal");
    }
    i += word.length();
    return node;
  }

  private void ws() {
    while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) {
      i++;
    }
  }

  private char peek() {
    if (i >= s.length()) {
      throw new IllegalArgumentException("unexpected end");
    }
    return s.charAt(i);
  }

  private char next() {
    char c = peek();
    i++;
    return c;
  }

  private void expect(char c) {
    if (next() != c) {
      throw new IllegalArgumentException("expected " + c);
    }
  }
}

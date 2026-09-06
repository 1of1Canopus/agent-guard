package com.housedevinci.agentguard.application;

import java.util.LinkedHashMap;
import java.util.Map;

/** Tiny JSON object writer for structured tool results and webhook payloads; no dependencies. */
public final class Json {

  private final Map<String, Object> fields = new LinkedHashMap<>();

  private Json() {}

  public static Json object() {
    return new Json();
  }

  public Json put(String key, Object value) {
    fields.put(key, value);
    return this;
  }

  @Override
  public String toString() {
    var sb = new StringBuilder("{");
    var first = true;
    for (var e : fields.entrySet()) {
      if (!first) {
        sb.append(',');
      }
      first = false;
      sb.append('"').append(escape(e.getKey())).append("\":");
      var v = e.getValue();
      if (v == null) {
        sb.append("null");
      } else if (v instanceof Number || v instanceof Boolean) {
        sb.append(v);
      } else if (v instanceof Json j) {
        sb.append(j);
      } else if (v instanceof RawJson r) {
        sb.append(r.text());
      } else {
        sb.append('"').append(escape(v.toString())).append('"');
      }
    }
    return sb.append('}').toString();
  }

  /** Pre-serialised JSON to embed as-is. */
  public record RawJson(String text) {}

  public static String escape(String s) {
    var sb = new StringBuilder(s.length() + 8);
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        default -> {
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
        }
      }
    }
    return sb.toString();
  }
}

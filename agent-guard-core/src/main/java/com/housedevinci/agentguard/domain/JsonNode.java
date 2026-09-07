package com.housedevinci.agentguard.domain;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A minimal JSON tree for the redactor and the canonical arguments hash. Kept in the domain so the
 * core has no JSON library dependency; parsing is strict RFC 8259 (escapes, numbers, literals).
 */
public sealed interface JsonNode {

  record JsonObject(Map<String, JsonNode> fields) implements JsonNode {
    public JsonObject {
      fields = new LinkedHashMap<>(Objects.requireNonNull(fields));
    }
  }

  record JsonArray(List<JsonNode> items) implements JsonNode {
    public JsonArray {
      items = List.copyOf(Objects.requireNonNull(items));
    }
  }

  record JsonString(String value) implements JsonNode {}

  /** Numbers keep their source text so canonical output never changes their representation. */
  record JsonNumber(String text) implements JsonNode {}

  record JsonBoolean(boolean value) implements JsonNode {}

  record JsonNull() implements JsonNode {}

  /** Serialises compactly; objects with sorted keys when {@code sortKeys} is true. */
  default String toJson(boolean sortKeys) {
    var sb = new StringBuilder();
    write(this, sb, sortKeys);
    return sb.toString();
  }

  private static void write(JsonNode n, StringBuilder sb, boolean sort) {
    switch (n) {
      case JsonObject o -> {
        sb.append('{');
        List<String> keys = new ArrayList<>(o.fields().keySet());
        if (sort) {
          keys.sort(null);
        }
        boolean first = true;
        for (String k : keys) {
          if (!first) {
            sb.append(',');
          }
          first = false;
          sb.append('"').append(JsonText.escape(k)).append("\":");
          write(o.fields().get(k), sb, sort);
        }
        sb.append('}');
      }
      case JsonArray a -> {
        sb.append('[');
        boolean first = true;
        for (JsonNode item : a.items()) {
          if (!first) {
            sb.append(',');
          }
          first = false;
          write(item, sb, sort);
        }
        sb.append(']');
      }
      case JsonString s -> sb.append('"').append(JsonText.escape(s.value())).append('"');
      case JsonNumber num -> sb.append(num.text());
      case JsonBoolean b -> sb.append(b.value());
      case JsonNull ignored -> sb.append("null");
    }
  }
}

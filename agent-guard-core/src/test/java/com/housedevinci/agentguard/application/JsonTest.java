package com.housedevinci.agentguard.application;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class JsonTest {
  @Test
  void escapes_and_nests() {
    var json =
        Json.object()
            .put("a", "x\"y\n")
            .put("n", 3)
            .put("b", true)
            .put("z", null)
            .put("o", Json.object().put("k", "v"))
            .put("raw", new Json.RawJson("[1,2]"))
            .toString();
    assertThat(json)
        .isEqualTo(
            "{\"a\":\"x\\\"y\\n\",\"n\":3,\"b\":true,\"z\":null,\"o\":{\"k\":\"v\"},\"raw\":[1,2]}");
    assertThat(Json.escape("")).isEqualTo("\\u0001");
  }
}

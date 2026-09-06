package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** the security review fuzz of {@link ArgumentRedactor}, flipped (L5): the redactor walks parsed JSON. */
class CipherProbeRedactorTest {

  private final ArgumentRedactor r = ArgumentRedactor.defaults();

  @Test
  void array_and_object_values_of_sensitive_keys_are_masked_whole() {
    assertThat(r.preview("{\"password\":[\"hunter2\"]}")).isEqualTo("{\"password\":\"***\"}");
    assertThat(r.preview("{\"api_key\":{\"value\":\"sk-live-123\"}}"))
        .doesNotContain("sk-live-123");
    assertThat(r.preview("{\"secret\":{\"v\":\"hunter2\"}}")).doesNotContain("hunter2");
    assertThat(r.preview("{\"pin\":1234,\"n\":5}")).isEqualTo("{\"pin\":\"***\",\"n\":5}");
  }

  @Test
  void unicode_escaped_keys_are_matched_after_unescaping() {
    assertThat(r.preview("{\"passw\\u006frd\":\"hunter2\"}")).doesNotContain("hunter2");
    assertThat(r.preview("{\"\\u0070assword\":\"hunter2\"}")).doesNotContain("hunter2");
  }

  @Test
  void line_and_direction_control_code_points_are_stripped() {
    assertThat(r.preview("{\"q\":\"a\u0085b\"}")).doesNotContain("\u0085").contains("ab");
    assertThat(r.preview("{\"q\":\"a\u202Eb\"}")).doesNotContain("\u202E");
  }

  @Test
  void unparseable_input_is_fully_masked() {
    assertThat(r.preview("password=hunter2 not json")).isEqualTo("\"***\"");
    assertThat(r.preview("{\"a\":")).isEqualTo("\"***\"");
    assertThat(r.redact("")).isEmpty();
  }

  @Test
  void probe_what_is_fine() {
    assertThat(r.preview("{\"password\":\"hunter2\"}")).doesNotContain("hunter2");
    assertThat(r.preview("{\"user_password\":\"hunter2\"}")).doesNotContain("hunter2");
    assertThat(r.preview("{\"x\":{\"token\":\"t1\"},\"y\":[{\"secret\":\"s1\"}]}"))
        .doesNotContain("t1")
        .doesNotContain("s1");
    assertThat(r.preview("{\"h\":\"Bearer abc.def-ghi\"}")).doesNotContain("abc.def");
    assertThat(r.preview("{\"q\":\"a\\nb\\rc\\u001b[31md\\u2028e\"}"))
        .doesNotContain("\n")
        .doesNotContain("\u001b")
        .doesNotContain("\u2028");
    // values keep their exact JSON representation
    assertThat(r.preview("{\"n\":1.50e3,\"b\":true,\"z\":null,\"s\":\"q\\\"uote\"}"))
        .isEqualTo("{\"n\":1.50e3,\"b\":true,\"z\":null,\"s\":\"q\\\"uote\"}");
  }
}

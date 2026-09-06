package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Cipher fuzz of {@link ArgumentRedactor} with adversarial JSON shapes. */
class CipherProbeRedactorTest {

  private final ArgumentRedactor r = ArgumentRedactor.defaults();

  @Test
  void probe_array_and_object_values_of_sensitive_keys_are_not_masked() {
    assertThat(r.preview("{\"password\":[\"hunter2\"]}")).contains("hunter2");
    assertThat(r.preview("{\"api_key\":{\"value\":\"sk-live-123\"}}")).contains("sk-live-123");
    assertThat(r.preview("{\"secret\":{\"v\":\"hunter2\"}}")).contains("hunter2");
  }

  @Test
  void probe_unicode_escaped_keys_bypass_the_key_match_on_the_spring_ai_path() {
    // Spring AI hands the model's JSON text to the guard verbatim; JSON allows \\u escapes in keys
    assertThat(r.preview("{\"passw\\u006frd\":\"hunter2\"}")).contains("hunter2");
    assertThat(r.preview("{\"\\u0070assword\":\"hunter2\"}")).contains("hunter2");
  }

  @Test
  void probe_line_and_direction_control_code_points_outside_cntrl_pass_through() {
    // U+0085 NEL is a line terminator for many log viewers; U+202E flips rendering direction
    assertThat(r.preview("{\"q\":\"a\u0085b\"}")).contains("\u0085");
    assertThat(r.preview("{\"q\":\"a\u202Eb\"}")).contains("\u202E");
  }

  @Test
  void probe_what_is_fine() {
    assertThat(r.preview("{\"password\":\"hunter2\"}")).doesNotContain("hunter2");
    assertThat(r.preview("{\"user_password\":\"hunter2\"}")).doesNotContain("hunter2");
    assertThat(r.preview("{\"x\":{\"token\":\"t1\"},\"y\":[{\"secret\":\"s1\"}]}"))
        .doesNotContain("t1")
        .doesNotContain("s1");
    assertThat(r.preview("{\"h\":\"Bearer abc.def-ghi\"}")).doesNotContain("abc.def");
    assertThat(r.preview("{\"q\":\"a\nb\rc\u001b[31md\u2028e\"}"))
        .doesNotContain("\n")
        .doesNotContain("\u001b")
        .doesNotContain("\u2028");
  }
}

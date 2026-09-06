package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

class ArgumentRedactorTest {

  private final ArgumentRedactor redactor = ArgumentRedactor.defaults();

  @Test
  void masks_values_of_sensitive_keys_case_insensitively() {
    var json =
        "{\"user\":\"bob\",\"Password\":\"hunter2\",\"api_key\":\"sk-123\",\"nested\":{\"token\":\"abc\"}}";
    var preview = redactor.preview(json);
    assertThat(preview).contains("\"user\":\"bob\"");
    assertThat(preview).doesNotContain("hunter2").doesNotContain("sk-123").doesNotContain("abc");
    assertThat(preview).contains("\"Password\":\"***\"").contains("\"token\":\"***\"");
  }

  @Test
  void caps_length_and_marks_truncation() {
    var redactor = new ArgumentRedactor(Set.of("password"), 32);
    var preview = redactor.preview("{\"text\":\"" + "x".repeat(200) + "\"}");
    assertThat(preview).hasSizeLessThanOrEqualTo(32 + ArgumentRedactor.TRUNCATION_MARK.length());
    assertThat(preview).endsWith(ArgumentRedactor.TRUNCATION_MARK);
  }

  @Test
  void strips_control_characters_and_newlines_against_log_injection() {
    var preview = redactor.preview("{\"a\":\"line1\\nline2\"}\n2024-01-01 INFO forged line[31m");
    assertThat(preview).doesNotContain("\n").doesNotContain("");
  }

  @Test
  void handles_null_and_non_json_input() {
    assertThat(redactor.preview(null)).isEmpty();
    assertThat(redactor.preview("not json with password=abc"))
        .isEqualTo("not json with password=abc");
  }

  @Test
  void masks_bearer_like_values_even_under_innocent_keys() {
    var preview = redactor.preview("{\"header\":\"Bearer eyJhbGciOiJIUzI1NiJ9.abc.def\"}");
    assertThat(preview).doesNotContain("eyJhbGciOiJIUzI1NiJ9");
  }
}

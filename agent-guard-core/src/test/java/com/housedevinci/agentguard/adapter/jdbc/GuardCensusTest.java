package com.housedevinci.agentguard.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/** The census's expected material, read from the bundled script; no database. */
class GuardCensusTest {

  private static String script() throws IOException {
    try (InputStream in = GuardCensusTest.class.getResourceAsStream(GuardCensus.SCRIPT)) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  /**
   * The three guard bodies are unchanged from 0.1.0 and 0.1.1: same md5 and length as the advisory
   * publishes, so an accidental edit to a guard body cannot pass unnoticed.
   */
  @Test
  void guard_bodies_are_the_ones_the_advisory_publishes() throws Exception {
    Matcher m =
        Pattern.compile(
                "CREATE OR REPLACE FUNCTION (\\w+)\\(\\) RETURNS trigger AS \\$\\$(.*?)\\$\\$",
                Pattern.DOTALL)
            .matcher(script());
    var md5 = MessageDigest.getInstance("MD5");
    var seen = new StringBuilder();
    while (m.find()) {
      String body = m.group(2);
      assertThat(body).doesNotContain("\r");
      seen.append(m.group(1))
          .append('=')
          .append(HexFormat.of().formatHex(md5.digest(body.getBytes(StandardCharsets.UTF_8))))
          .append('/')
          .append(body.length())
          .append(' ');
    }
    assertThat(seen.toString().strip())
        .isEqualTo(
            "agentguard_audit_append_only=ae7e0faf7d763b3bb9b39525d16aeeb0/86"
                + " agentguard_audit_anchor_monotonic=99b20f00dd8381192262b58d1d478f26/420"
                + " agentguard_audit_anchor_append_only=2a3c05a9d5a0343ed45496075f981264/93");
  }

  @Test
  void a_script_that_does_not_yield_the_three_guard_functions_is_unverifiable() throws Exception {
    String damaged = script().replace("agentguard_audit_anchor_monotonic() RETURNS", "x() RETURNS");
    assertThatThrownBy(() -> GuardCensus.fromBundledScript(damaged))
        .isInstanceOf(AgentGuardException.class)
        .satisfies(
            e ->
                assertThat(((AgentGuardException) e).code())
                    .isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE));
    assertThat(GuardCensus.fromBundledScript(script())).isNotNull();
  }

  @Test
  void the_bundled_script_arms_enable_always_only_after_every_conditional_block() throws Exception {
    String s = script();
    int lastConditional = s.lastIndexOf("IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger");
    int firstAlways = s.indexOf("ENABLE ALWAYS TRIGGER agentguard_");
    assertThat(lastConditional).isPositive();
    assertThat(firstAlways).isGreaterThan(lastConditional);
    assertThat(s).doesNotContain("FROM pg_trigger WHERE tgname");
    assertThat(s.split("ENABLE ALWAYS TRIGGER agentguard_", -1)).hasSize(6);
  }
}

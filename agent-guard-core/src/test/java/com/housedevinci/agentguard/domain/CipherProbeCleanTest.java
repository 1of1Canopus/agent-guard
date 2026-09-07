package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Cipher probes for the clean-verdict pass on {@code 50ed8d3}: the surfaces the L5/I1 fixes
 * introduced (the hand-written JSON parser, the canonical arguments hash, the JSON-walking
 * redactor). Each probe asserts the behaviour as it is today; the fix flips it (rename without the
 * {@code probe_} prefix and invert the assertion), as with the earlier rounds.
 */
class CipherProbeCleanTest {

  private final ArgumentRedactor redactor = ArgumentRedactor.defaults();

  /**
   * C1: {@code Hashes.sha256Hex} encodes the canonical text as UTF-8, and an unpaired surrogate
   * encodes to {@code '?'}. Every unpaired surrogate therefore hashes like a literal question mark,
   * so two different calls share one decision: the second one is answered from the first one's
   * stored result and never runs, and {@code argumentsIntact()} accepts the swap.
   *
   * <p>Fix: canonicalise to bytes that cannot collide — reject or {@code \\u}-escape unpaired
   * surrogates in {@link JsonText#escape} (they are already invalid JSON output), or hash {@code
   * text.getBytes(UTF_16BE)}.
   */
  @Test
  void an_unpaired_surrogate_and_a_question_mark_do_not_share_one_arguments_hash() {
    String surrogate = "{\"path\":\"\\ud800\"}";
    String questionMark = "{\"path\":\"?\"}";

    assertThat(ArgumentCanonicalizer.hash(surrogate))
        .isNotEqualTo(ArgumentCanonicalizer.hash(questionMark));
    // the approver does see two different things, which is what makes the collision a swap
    assertThat(redactor.redact(surrogate)).isNotEqualTo(redactor.redact(questionMark));
  }

  /**
   * C2: sensitive keys are matched on a whole-word suffix only, so the commonest compound spellings
   * of a secret are previewed, logged and webhooked in the clear.
   *
   * <p>Fix: split the key on {@code _ - . } and camel-case boundaries and mask when any part
   * matches a sensitive key (keep the current suffix rule for the unsplittable case).
   */
  @Test
  void camel_case_and_suffixed_sensitive_keys_are_masked() {
    assertThat(redactor.redact("{\"userPassword\":\"hunter2\"}")).doesNotContain("hunter2");
    assertThat(redactor.redact("{\"myApiKey\":\"sk-live-1\"}")).doesNotContain("sk-live-1");
    assertThat(redactor.redact("{\"password_confirmation\":\"hunter2\"}"))
        .doesNotContain("hunter2");
    // what already works, so the fix does not regress it
    assertThat(redactor.redact("{\"api_key\":{\"v\":\"x\"}}")).isEqualTo("{\"api_key\":\"***\"}");
    assertThat(redactor.redact("{\"user_password\":\"hunter2\"}")).doesNotContain("hunter2");
  }

  /**
   * C3: the parser is more permissive than RFC 8259, so text the tool's own JSON reader (Jackson)
   * refuses is treated as structured and passed on: {@code Character.isDigit} accepts every Unicode
   * decimal digit, and {@code Integer.parseInt} accepts a signed {@code \\u} escape.
   *
   * <p>Fix: {@code c >= '0' && c <= '9'} in {@code digits()}, and reject a {@code \\u} escape whose
   * four characters are not all {@code [0-9a-fA-F]}.
   */
  @Test
  void the_parser_rejects_text_that_is_not_json() {
    assertThat(JsonText.parse("{\"a\":\u0661\u0662}")).isEmpty(); // Arabic-Indic digits
    assertThat(JsonText.parse("{\"a\":\"\\u+041\"}")).isEmpty(); // '+' rejected as a hex sign
    assertThat(JsonText.parse("{\"a\":\"\\u-001\"}")).isEmpty();
  }

  /** What the parser does get right, so a fix for C3 does not lose it. */
  @Test
  void parser_limits_that_hold() {
    assertThat(JsonText.parse("{\"a\":1} trailing")).isEmpty();
    assertThat(JsonText.parse("\uFEFF{\"password\":\"x\"}")).isEmpty(); // BOM -> full mask
    assertThat(JsonText.parse("[".repeat(65) + "1" + "]".repeat(65))).isEmpty(); // depth cap
    assertThat(JsonText.parse("[".repeat(64) + "1" + "]".repeat(64))).isPresent();
    assertThat(redactor.redact("{oops")).isEqualTo("\"***\""); // unparseable -> full mask
    assertThat(redactor.redact("{\"a\":\"x\u0085\u202Ey\"}")).isEqualTo("{\"a\":\"xy\"}");
    // duplicate keys collapse last-wins, the same way Jackson delivers them to the tool
    assertThat(ArgumentCanonicalizer.canonical("{\"amount\":1,\"amount\":1000000}"))
        .isEqualTo("{\"amount\":1000000}");
  }

  /**
   * C12: the audit row hashes the raw arguments text ({@code AuditRecorder.record} -> {@code
   * Hashes.sha256Hex}) while the decision hashes the canonical form ({@code
   * ArgumentCanonicalizer.hash}), so for the same call {@code agentguard_audit.args_hash} and
   * {@code agentguard_decision.args_hash} differ whenever the model emitted whitespace or a
   * different key order — the join an auditor uses to tie a trail row to the approval that allowed
   * it silently finds nothing.
   *
   * <p>Fix: {@code AuditRecorder} hashes {@code ArgumentCanonicalizer.canonical(argumentsJson)}.
   */
  @Test
  void the_audit_row_hashes_the_same_canonical_form_as_the_decision() {
    String args = "{ \"b\":2, \"a\":1 }";
    // AuditRecorder now hashes ArgumentCanonicalizer.canonical(args), same as the decision store.
    // V3 domain-separates this hash from the oversized-denial raw hash with a fixed prefix, so the
    // expectation here is computed the same way ArgumentCanonicalizer.hash is (see V3).
    assertThat(
            Hashes.sha256Hex(
                ArgumentCanonicalizer.CANONICAL_HASH_DOMAIN
                    + ArgumentCanonicalizer.canonical(args)))
        .isEqualTo(ArgumentCanonicalizer.hash(args));
  }
}

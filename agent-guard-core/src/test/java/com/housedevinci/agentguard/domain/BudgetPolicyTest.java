package com.housedevinci.agentguard.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class BudgetPolicyTest {

  @Test
  void would_exceed_mirrors_kit_quota_policy() {
    assertThat(BudgetPolicy.wouldExceed(3, 2, 1)).isFalse();
    assertThat(BudgetPolicy.wouldExceed(3, 3, 1)).isTrue();
    assertThat(BudgetPolicy.wouldExceed(3, 0, 4)).isTrue();
  }

  @Test
  void window_start_is_aligned_to_the_window_size() {
    var limit =
        new BudgetLimit(BudgetScope.PRINCIPAL, BudgetKind.TOOL_CALLS, Duration.ofMinutes(10), 5);
    var now = Instant.parse("2026-09-06T10:07:33Z");
    assertThat(limit.windowStart(now)).isEqualTo(Instant.parse("2026-09-06T10:00:00Z"));
    assertThat(limit.windowEnd(now)).isEqualTo(Instant.parse("2026-09-06T10:10:00Z"));
  }

  @Test
  void key_is_stable_per_subject_and_window() {
    var limit = new BudgetLimit(BudgetScope.TENANT, BudgetKind.TOKENS, Duration.ofDays(1), 1000);
    var now = Instant.parse("2026-09-06T10:07:33Z");
    var k1 = limit.key("acme", now);
    var k2 = limit.key("acme", now.plusSeconds(3600));
    var k3 = limit.key("acme", now.plus(Duration.ofDays(1)));
    assertThat(k1).isEqualTo(k2).isNotEqualTo(k3);
    assertThat(k1).startsWith("agentguard:budget:TENANT:TOKENS:acme:");
  }

  @Test
  void limit_validation() {
    assertThatThrownBy(
            () -> new BudgetLimit(BudgetScope.PRINCIPAL, BudgetKind.STEPS, Duration.ZERO, 1))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () -> new BudgetLimit(BudgetScope.PRINCIPAL, BudgetKind.STEPS, Duration.ofHours(1), 0))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void long_subjects_are_hashed_into_the_key() {
    var limit = new BudgetLimit(BudgetScope.CONVERSATION, BudgetKind.STEPS, Duration.ofHours(1), 5);
    var key = limit.key("x".repeat(600), Instant.EPOCH);
    assertThat(key).contains(":sha256:").hasSizeLessThan(200);
    assertThat(limit.key("short", Instant.EPOCH)).contains(":short:");
  }
}

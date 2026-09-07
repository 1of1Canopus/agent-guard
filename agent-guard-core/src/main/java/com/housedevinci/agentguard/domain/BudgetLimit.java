package com.housedevinci.agentguard.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * A cap on {@code kind} per {@code scope} inside a fixed-size, epoch-aligned window.
 *
 * @param scope whose counter
 * @param kind what is counted
 * @param window window size (aligned to the epoch)
 * @param limit maximum units per window
 */
public record BudgetLimit(BudgetScope scope, BudgetKind kind, Duration window, long limit) {

  public BudgetLimit {
    Objects.requireNonNull(scope, "scope");
    Objects.requireNonNull(kind, "kind");
    Objects.requireNonNull(window, "window");
    if (window.isZero() || window.isNegative()) {
      throw new IllegalArgumentException("window must be positive");
    }
    if (limit <= 0) {
      throw new IllegalArgumentException("limit must be positive");
    }
  }

  public Instant windowStart(Instant now) {
    long size = window.toMillis();
    return Instant.ofEpochMilli(Math.floorDiv(now.toEpochMilli(), size) * size);
  }

  public Instant windowEnd(Instant now) {
    return windowStart(now).plus(window);
  }

  /** Longest subject kept verbatim in a key; longer ones are replaced by their SHA-256. */
  public static final int MAX_SUBJECT_LENGTH = 128;

  /** Store key for {@code subject} in the window containing {@code now}. */
  public String key(String subject, Instant now) {
    String s =
        subject.length() > MAX_SUBJECT_LENGTH ? "sha256:" + Hashes.sha256Hex(subject) : subject;
    return "agentguard:budget:"
        + scope
        + ":"
        + kind
        + ":"
        + s
        + ":"
        + windowStart(now).getEpochSecond();
  }
}

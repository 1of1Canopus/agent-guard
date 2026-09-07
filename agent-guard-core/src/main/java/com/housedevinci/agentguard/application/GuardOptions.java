package com.housedevinci.agentguard.application;

import java.time.Duration;
import java.util.Objects;

/**
 * Knobs of the guard pipeline.
 *
 * @param maxPendingPerPrincipal decisions one principal may have waiting at once
 * @param maxArgumentBytes largest arguments (UTF-8 bytes) a parked call may carry
 * @param replayWindow how far back an identical call is matched to an existing decision
 * @param includeToolMessage forward the tool's own exception message to the model
 */
public record GuardOptions(
    int maxPendingPerPrincipal,
    int maxArgumentBytes,
    Duration replayWindow,
    boolean includeToolMessage) {

  public static final GuardOptions DEFAULTS =
      new GuardOptions(20, 64 * 1024, Duration.ofHours(1), false);

  public GuardOptions {
    if (maxPendingPerPrincipal < 1 || maxArgumentBytes < 1) {
      throw new IllegalArgumentException("guard limits must be positive");
    }
    Objects.requireNonNull(replayWindow, "replayWindow");
    if (replayWindow.isZero() || replayWindow.isNegative()) {
      throw new IllegalArgumentException("replayWindow must be positive");
    }
  }
}

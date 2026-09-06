package com.housedevinci.agentguard.application;

/**
 * Caps on parking, so a prompt-injected model cannot flood approvers or the store.
 *
 * @param maxPendingPerPrincipal decisions one principal may have waiting at once
 * @param maxArgumentBytes largest arguments (UTF-8 bytes) a parked call may carry
 */
public record ApprovalLimits(int maxPendingPerPrincipal, int maxArgumentBytes) {

  public static final ApprovalLimits DEFAULTS = new ApprovalLimits(20, 64 * 1024);

  public ApprovalLimits {
    if (maxPendingPerPrincipal < 1 || maxArgumentBytes < 1) {
      throw new IllegalArgumentException("approval limits must be positive");
    }
  }
}

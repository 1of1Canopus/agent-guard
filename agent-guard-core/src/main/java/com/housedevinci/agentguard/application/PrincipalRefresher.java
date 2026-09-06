package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.Principal;
import java.util.Optional;

/**
 * Re-reads a principal's current roles, scopes and tenant when an approved call is about to run, so
 * a revocation between park and approve takes effect. Default: identity (the stored principal).
 */
@FunctionalInterface
public interface PrincipalRefresher {

  /** Empty means "unchanged, use the stored principal". */
  Optional<Principal> refresh(Principal stored);

  static PrincipalRefresher identity() {
    return stored -> Optional.empty();
  }
}

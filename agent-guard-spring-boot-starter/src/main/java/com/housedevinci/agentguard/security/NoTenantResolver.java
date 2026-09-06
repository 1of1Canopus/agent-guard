package com.housedevinci.agentguard.security;

import java.util.Optional;
import org.springframework.security.core.Authentication;

/**
 * The default: single tenant. Replace it before configuring TENANT budgets or tenants= policies.
 */
public final class NoTenantResolver implements TenantResolver {
  @Override
  public Optional<String> tenantOf(Authentication authentication) {
    return Optional.empty();
  }
}

package com.housedevinci.agentguard.security;

import java.util.Optional;
import org.springframework.security.core.Authentication;

/**
 * The default: single tenant, except during a resumed call, where the tenant stored with the
 * decision is kept ({@link RunAsAuthentication}). Replace it before configuring TENANT budgets or
 * {@code tenants=} policies; custom resolvers should handle {@link RunAsAuthentication} the same
 * way (the default {@link SecurityContextPrincipalResolver} already short-circuits on it).
 */
public final class NoTenantResolver implements TenantResolver {
  @Override
  public Optional<String> tenantOf(Authentication authentication) {
    if (authentication instanceof RunAsAuthentication runAs) {
      return runAs.agentGuardPrincipal().tenantId();
    }
    return Optional.empty();
  }
}

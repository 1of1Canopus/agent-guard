package com.housedevinci.agentguard.security;

import java.util.Optional;
import org.springframework.security.core.Authentication;

/** Maps an authentication to a tenant id (a JWT claim, a header, a Tenantify context). */
@FunctionalInterface
public interface TenantResolver {
  Optional<String> tenantOf(Authentication authentication);
}

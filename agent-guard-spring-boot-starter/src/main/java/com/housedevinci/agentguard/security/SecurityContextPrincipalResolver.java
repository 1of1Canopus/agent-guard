package com.housedevinci.agentguard.security;

import com.housedevinci.agentguard.domain.Principal;
import java.util.HashSet;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Builds the {@link Principal} from the Spring Security context: {@code ROLE_X} authorities become
 * roles, {@code SCOPE_X} authorities become scopes, the tenant comes from the {@link
 * TenantResolver}. Unauthenticated callers are {@link Principal#anonymous()}.
 */
public final class SecurityContextPrincipalResolver implements PrincipalResolver {

  private final TenantResolver tenantResolver;

  public SecurityContextPrincipalResolver(TenantResolver tenantResolver) {
    this.tenantResolver = tenantResolver;
  }

  @Override
  public Principal resolve() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
      return Principal.anonymous();
    }
    return from(auth);
  }

  public Principal from(Authentication auth) {
    Set<String> roles = new HashSet<>();
    Set<String> scopes = new HashSet<>();
    for (GrantedAuthority a : auth.getAuthorities()) {
      String name = a.getAuthority();
      if (name == null) {
        continue;
      }
      if (name.startsWith("ROLE_")) {
        roles.add(name.substring(5));
      } else if (name.startsWith("SCOPE_")) {
        scopes.add(name.substring(6));
      } else {
        roles.add(name);
      }
    }
    return new Principal(auth.getName(), roles, scopes, tenantResolver.tenantOf(auth).orElse(null));
  }
}

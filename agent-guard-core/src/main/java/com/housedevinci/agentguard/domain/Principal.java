package com.housedevinci.agentguard.domain;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Who is calling the tool. Built by the host application (from Spring Security, an API key, an
 * MCP session) and evaluated by {@link ToolPolicyEvaluator}.
 *
 * @param id stable identifier (username, subject claim, API-key id); never null
 * @param roles granted roles without any {@code ROLE_} prefix
 * @param scopes granted OAuth2 scopes without any {@code SCOPE_} prefix
 * @param tenant tenant id, or null / blank when the application is single tenant
 */
public record Principal(String id, Set<String> roles, Set<String> scopes, String tenant) {

  public static final String ANONYMOUS_ID = "anonymous";

  public Principal {
    Objects.requireNonNull(id, "principal id");
    roles = Set.copyOf(Objects.requireNonNullElse(roles, Set.of()));
    scopes = Set.copyOf(Objects.requireNonNullElse(scopes, Set.of()));
    tenant = (tenant == null || tenant.isBlank()) ? null : tenant.strip();
  }

  /** An unauthenticated caller: no roles, no scopes, no tenant. */
  public static Principal anonymous() {
    return new Principal(ANONYMOUS_ID, Set.of(), Set.of(), null);
  }

  public Optional<String> tenantId() {
    return Optional.ofNullable(tenant);
  }

  public boolean hasAnyRole(Set<String> wanted) {
    return wanted.stream().anyMatch(roles::contains);
  }

  public boolean hasAnyScope(Set<String> wanted) {
    return wanted.stream().anyMatch(scopes::contains);
  }
}

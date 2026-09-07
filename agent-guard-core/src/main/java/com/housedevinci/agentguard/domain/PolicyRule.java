package com.housedevinci.agentguard.domain;

import java.util.Objects;
import java.util.Set;

/**
 * The evaluated form of {@code @ToolPolicy}. Empty sets mean "no restriction on that axis".
 *
 * @param roles any-of roles; empty = no role restriction
 * @param scopes any-of scopes; empty = no scope restriction
 * @param tenants any-of tenants; empty = no tenant restriction
 * @param sideEffect what the tool does; decides whether approval is required
 */
public record PolicyRule(
    Set<String> roles, Set<String> scopes, Set<String> tenants, SideEffect sideEffect) {

  public PolicyRule {
    roles = Set.copyOf(Objects.requireNonNullElse(roles, Set.of()));
    scopes = Set.copyOf(Objects.requireNonNullElse(scopes, Set.of()));
    tenants = Set.copyOf(Objects.requireNonNullElse(tenants, Set.of()));
    Objects.requireNonNull(sideEffect, "side effect");
  }

  /** A rule that restricts nobody and only carries the side effect. */
  public static PolicyRule unrestricted(SideEffect sideEffect) {
    return new PolicyRule(Set.of(), Set.of(), Set.of(), sideEffect);
  }
}

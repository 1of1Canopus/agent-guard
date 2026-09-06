package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import java.util.Objects;
import java.util.Optional;

/**
 * Finds the rule for a tool: registry entry, else a side-effect hint from the integration (MCP
 * {@code readOnlyHint} / {@code destructiveHint}), else {@link UnregisteredToolBehaviour}.
 */
public final class PolicyLookup {

  private final ToolPolicyRegistry registry;
  private final UnregisteredToolBehaviour unregistered;

  public PolicyLookup(ToolPolicyRegistry registry, UnregisteredToolBehaviour unregistered) {
    this.registry = Objects.requireNonNull(registry, "registry");
    this.unregistered = Objects.requireNonNull(unregistered, "unregistered");
  }

  /** Empty means: deny, the tool is unknown and the behaviour is DENY. */
  public Optional<PolicyRule> resolve(String toolName, Optional<SideEffect> hint) {
    var registered = registry.find(toolName);
    if (registered.isPresent()) {
      return registered;
    }
    if (hint.isPresent()) {
      return Optional.of(PolicyRule.unrestricted(hint.get()));
    }
    return switch (unregistered) {
      case DENY -> Optional.empty();
      case ALLOW -> Optional.of(PolicyRule.unrestricted(SideEffect.READ));
      case REQUIRE_APPROVAL -> Optional.of(PolicyRule.unrestricted(SideEffect.WRITE));
    };
  }

  public ToolPolicyRegistry registry() {
    return registry;
  }
}

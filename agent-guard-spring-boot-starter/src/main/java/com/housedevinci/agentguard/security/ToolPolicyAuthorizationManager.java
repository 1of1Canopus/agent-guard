package com.housedevinci.agentguard.security;

import com.housedevinci.agentguard.application.PolicyLookup;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.domain.ErrorCodes;
import com.housedevinci.agentguard.domain.PolicyDecision;
import com.housedevinci.agentguard.domain.ToolPolicyEvaluator;
import com.housedevinci.agentguard.domain.ToolRef;
import java.util.Optional;
import java.util.function.Supplier;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

/**
 * Spring Security view of the tool policy, so it composes with {@code @PreAuthorize} and {@code
 * AuthorizationManager} chains. The result carries the domain {@link PolicyDecision}.
 */
public final class ToolPolicyAuthorizationManager implements AuthorizationManager<ToolInvocation> {

  /** Granted only for ALLOW; REQUIRE_APPROVAL is not granted but not a plain deny either. */
  public record Result(PolicyDecision decision) implements AuthorizationResult {
    @Override
    public boolean isGranted() {
      return decision.kind() == PolicyDecision.Kind.ALLOW;
    }
  }

  private final PolicyLookup policies;
  private final ToolPolicyEvaluator evaluator;
  private final SecurityContextPrincipalResolver resolver;

  public ToolPolicyAuthorizationManager(
      PolicyLookup policies, ToolPolicyEvaluator evaluator, TenantResolver tenantResolver) {
    this.policies = policies;
    this.evaluator = evaluator;
    this.resolver = new SecurityContextPrincipalResolver(tenantResolver);
  }

  @Override
  public AuthorizationResult authorize(
      Supplier<? extends Authentication> authentication, ToolInvocation invocation) {
    var auth = authentication.get();
    var principal = auth == null ? invocation.principal() : resolver.of(auth);
    var rule = policies.resolve(invocation.toolName(), Optional.empty());
    if (rule.isEmpty()) {
      return new Result(PolicyDecision.deny(ErrorCodes.POLICY_UNREGISTERED, "tool has no policy"));
    }
    return new Result(
        evaluator.evaluate(
            rule.get(), principal, new ToolRef(invocation.toolName(), rule.get().sideEffect())));
  }
}

package com.housedevinci.agentguard.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.application.PolicyLookup;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.application.UnregisteredToolBehaviour;
import com.housedevinci.agentguard.domain.PolicyDecision;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolPolicyEvaluator;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class ToolPolicyAuthorizationManagerTest {

  private final ToolPolicyRegistry registry = new ToolPolicyRegistry();
  private final ToolPolicyAuthorizationManager manager =
      new ToolPolicyAuthorizationManager(
          new PolicyLookup(registry, UnregisteredToolBehaviour.DENY),
          ToolPolicyEvaluator.defaults(),
          new NoTenantResolver());

  @Test
  void anonymous_tokens_map_to_the_anonymous_principal_and_are_denied() {
    registry.register("read", new PolicyRule(Set.of("USER"), Set.of(), Set.of(), SideEffect.READ));
    var anonymous =
        new AnonymousAuthenticationToken(
            "key", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
    var inv = ToolInvocation.of(Principal.anonymous(), "read", "{}");
    var result = (ToolPolicyAuthorizationManager.Result) manager.authorize(() -> anonymous, inv);
    assertThat(result.isGranted()).isFalse();
    assertThat(result.decision()).isInstanceOf(PolicyDecision.Deny.class);
    // same for the resolver directly: no "anonymousUser" id with ROLE_ANONYMOUS
    var resolver = new SecurityContextPrincipalResolver(new NoTenantResolver());
    assertThat(resolver.of(anonymous)).isEqualTo(Principal.anonymous());
    assertThat(resolver.of(null)).isEqualTo(Principal.anonymous());
    var unauthenticated = new TestingAuthenticationToken("x", "y");
    assertThat(resolver.of(unauthenticated)).isEqualTo(Principal.anonymous());
  }

  @Test
  void authenticated_user_with_the_role_is_granted() {
    registry.register("read", new PolicyRule(Set.of("USER"), Set.of(), Set.of(), SideEffect.READ));
    var auth = new TestingAuthenticationToken("bob", "n/a", "ROLE_USER");
    auth.setAuthenticated(true);
    var inv = ToolInvocation.of(Principal.anonymous(), "read", "{}");
    assertThat(manager.authorize(() -> auth, inv).isGranted()).isTrue();
  }
}

package com.housedevinci.agentguard.security;

import com.housedevinci.agentguard.domain.Principal;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * The identity an approved call runs with: rebuilt from the {@link Principal} stored with the
 * decision (roles as {@code ROLE_x}, scopes as {@code SCOPE_x}), never the approver's. Only {@link
 * SecurityContextResumeContextProvider} can mint one; it is never serializable (so no session store
 * can carry a forged one) and cannot be re-marked authenticated from outside.
 */
public final class RunAsAuthentication extends AbstractAuthenticationToken {

  private final transient Principal principal;

  RunAsAuthentication(Principal principal) {
    super(authorities(principal));
    this.principal = principal;
    super.setAuthenticated(true);
  }

  private static List<GrantedAuthority> authorities(Principal p) {
    var out = new ArrayList<GrantedAuthority>();
    p.roles().stream().sorted().forEach(r -> out.add(new SimpleGrantedAuthority("ROLE_" + r)));
    p.scopes().stream().sorted().forEach(s -> out.add(new SimpleGrantedAuthority("SCOPE_" + s)));
    return out;
  }

  @Override
  public void setAuthenticated(boolean authenticated) {
    if (authenticated) {
      throw new IllegalArgumentException(
          "RunAsAuthentication is only created authenticated by SecurityContextResumeContextProvider");
    }
    super.setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return "";
  }

  @Override
  public Object getPrincipal() {
    return principal.id();
  }

  @Override
  public String getName() {
    return principal.id();
  }

  public Principal agentGuardPrincipal() {
    return principal;
  }

  private void writeObject(ObjectOutputStream out) throws IOException {
    throw new NotSerializableException(RunAsAuthentication.class.getName());
  }

  private void readObject(ObjectInputStream in) throws IOException {
    throw new NotSerializableException(RunAsAuthentication.class.getName());
  }
}

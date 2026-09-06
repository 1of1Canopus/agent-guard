package com.housedevinci.agentguard.security;

import com.housedevinci.agentguard.application.ResumeContextProvider;
import com.housedevinci.agentguard.domain.PendingDecision;
import java.util.concurrent.Callable;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Runs the approved call inside a fresh Spring Security context holding a {@link
 * RunAsAuthentication} for the parking principal, then restores the approver's context.
 */
public final class SecurityContextResumeContextProvider implements ResumeContextProvider {

  @Override
  public <T> T runAs(PendingDecision decision, Callable<T> action) throws Exception {
    SecurityContext previous = SecurityContextHolder.getContext();
    SecurityContext runAs = SecurityContextHolder.createEmptyContext();
    runAs.setAuthentication(new RunAsAuthentication(decision.principal()));
    SecurityContextHolder.setContext(runAs);
    try {
      return action.call();
    } finally {
      SecurityContextHolder.setContext(previous);
    }
  }
}

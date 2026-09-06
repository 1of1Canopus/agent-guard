package com.housedevinci.agentguard.application;

import com.housedevinci.agentguard.domain.PendingDecision;
import java.util.concurrent.Callable;

/**
 * Runs an approved call inside the identity of the principal that parked it, not the approver's.
 * The starter's implementation rebuilds a Spring Security context from the stored {@link
 * com.housedevinci.agentguard.domain.Principal}; hosts with richer contexts (tenant filters, MDC)
 * provide their own bean.
 */
@FunctionalInterface
public interface ResumeContextProvider {

  <T> T runAs(PendingDecision decision, Callable<T> action) throws Exception;

  /** No context switching; the call runs on the approver's thread as is. */
  static ResumeContextProvider none() {
    return new ResumeContextProvider() {
      @Override
      public <T> T runAs(PendingDecision decision, Callable<T> action) throws Exception {
        return action.call();
      }
    };
  }
}

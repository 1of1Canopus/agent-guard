package com.housedevinci.agentguard.web;

import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.security.PrincipalResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;

/** Opt-in REST endpoints (approve / reject / list / audit). */
@AutoConfiguration(after = AgentGuardAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DispatcherServlet.class)
@ConditionalOnProperty(prefix = "agentguard.endpoints", name = "enabled", havingValue = "true")
public class AgentGuardWebAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AgentGuardEndpoints agentGuardEndpoints(ApprovalService approvals, AuditReader audit, PrincipalResolver principals) {
    return new AgentGuardEndpoints(approvals, audit, principals);
  }
}

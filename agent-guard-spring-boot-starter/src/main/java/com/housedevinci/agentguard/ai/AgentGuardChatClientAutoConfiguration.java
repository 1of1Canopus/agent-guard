package com.housedevinci.agentguard.ai;

import com.housedevinci.agentguard.application.BudgetEnforcer;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.security.PrincipalResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * ChatClient integration (its own auto-configuration so the advisor types stay optional): the usage
 * advisor records model tokens against {@code kind: TOKENS} budgets. Spring AI's ChatClient
 * auto-configuration picks up {@code Advisor} beans as defaults.
 */
@AutoConfiguration(after = AgentGuardAutoConfiguration.class)
@ConditionalOnClass(name = "org.springframework.ai.chat.client.ChatClient")
@ConditionalOnProperty(prefix = "agentguard", name = "enabled", havingValue = "true")
public class AgentGuardChatClientAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AgentGuardUsageAdvisor agentGuardUsageAdvisor(
      BudgetEnforcer budgets, PrincipalResolver principals) {
    return new AgentGuardUsageAdvisor(budgets, principals);
  }
}

package com.housedevinci.agentguard.ai;

import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.security.PrincipalResolver;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/** Spring AI tool-calling integration: every {@code ToolCallback} bean is guarded. */
@AutoConfiguration(after = AgentGuardAutoConfiguration.class)
@ConditionalOnClass(ToolCallback.class)
@ConditionalOnProperty(prefix = "agentguard", name = "enabled", havingValue = "true")
public class AgentGuardSpringAiAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AgentGuard agentGuard(ToolGuard guard, PrincipalResolver principals) {
    return new AgentGuard(guard, principals);
  }

  @Bean
  public static ToolCallbackGuardBeanPostProcessor toolCallbackGuardBeanPostProcessor(
      BeanFactory beanFactory) {
    return new ToolCallbackGuardBeanPostProcessor(beanFactory);
  }
}

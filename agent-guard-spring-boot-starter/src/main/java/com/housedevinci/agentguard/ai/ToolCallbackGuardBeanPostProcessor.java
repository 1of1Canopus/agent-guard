package com.housedevinci.agentguard.ai;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;

/** Wraps every {@link ToolCallback} and {@link ToolCallbackProvider} bean. */
public final class ToolCallbackGuardBeanPostProcessor implements BeanPostProcessor {

  private final BeanFactory beanFactory;
  private volatile AgentGuard agentGuard;

  public ToolCallbackGuardBeanPostProcessor(BeanFactory beanFactory) {
    this.beanFactory = beanFactory;
  }

  private AgentGuard agentGuard() {
    if (agentGuard == null) {
      agentGuard = beanFactory.getBean(AgentGuard.class);
    }
    return agentGuard;
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) {
    if (bean instanceof ToolCallback cb) {
      return agentGuard().guard(cb);
    }
    if (bean instanceof ToolCallbackProvider provider) {
      return agentGuard().guard(provider);
    }
    return bean;
  }
}

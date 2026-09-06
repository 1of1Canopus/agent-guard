package com.housedevinci.agentguard.ai;

import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * Wraps every {@link ToolCallback}, {@link ToolCallbackProvider}, {@link ToolCallbackResolver} and
 * {@link ToolCallingManager} bean, so tools are guarded whichever way the model reaches them.
 */
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
    if (bean instanceof ToolCallingManager manager) {
      return agentGuard().guard(manager);
    }
    if (bean instanceof ToolCallbackResolver resolver) {
      return agentGuard().guard(resolver);
    }
    return bean;
  }
}

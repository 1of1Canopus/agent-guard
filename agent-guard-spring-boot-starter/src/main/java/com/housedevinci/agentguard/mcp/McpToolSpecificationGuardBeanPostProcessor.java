package com.housedevinci.agentguard.mcp;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * Replaces every MCP tool specification bean, single or {@code List}, with a guarded copy before
 * the MCP server collects them; fails startup on async specifications.
 */
public final class McpToolSpecificationGuardBeanPostProcessor implements BeanPostProcessor {

  private final BeanFactory beanFactory;
  private volatile McpToolGuard mcpToolGuard;

  public McpToolSpecificationGuardBeanPostProcessor(BeanFactory beanFactory) {
    this.beanFactory = beanFactory;
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) {
    if (!(bean instanceof java.util.List<?>)
        && !bean.getClass().getName().startsWith("io.modelcontextprotocol.server.")) {
      return bean;
    }
    if (mcpToolGuard == null) {
      mcpToolGuard = beanFactory.getBean(McpToolGuard.class);
    }
    return mcpToolGuard.guardBean(bean, beanName);
  }
}

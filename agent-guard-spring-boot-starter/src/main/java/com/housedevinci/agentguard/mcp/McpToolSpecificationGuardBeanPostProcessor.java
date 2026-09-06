package com.housedevinci.agentguard.mcp;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * Replaces every {@code List<SyncToolSpecification>} bean (Spring AI publishes them from
 * {@code @McpTool} beans and from {@code ToolCallback} beans) with a guarded copy before the MCP
 * server collects them.
 */
public final class McpToolSpecificationGuardBeanPostProcessor implements BeanPostProcessor {

  private final BeanFactory beanFactory;
  private volatile McpToolGuard mcpToolGuard;

  public McpToolSpecificationGuardBeanPostProcessor(BeanFactory beanFactory) {
    this.beanFactory = beanFactory;
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) {
    if (!(bean instanceof java.util.List<?>)) {
      return bean;
    }
    if (mcpToolGuard == null) {
      mcpToolGuard = beanFactory.getBean(McpToolGuard.class);
    }
    return mcpToolGuard.guardListIfApplicable(bean);
  }
}

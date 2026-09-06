package com.housedevinci.agentguard.mcp;

import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.autoconfigure.GuardCoverage;
import com.housedevinci.agentguard.security.PrincipalResolver;
import io.modelcontextprotocol.server.McpServerFeatures;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import tools.jackson.databind.json.JsonMapper;

/** MCP server integration: every {@code @McpTool} (and converted ToolCallback) is guarded. */
@AutoConfiguration(after = AgentGuardAutoConfiguration.class)
@ConditionalOnClass({McpServerFeatures.class, JsonMapper.class})
@ConditionalOnProperty(prefix = "agentguard", name = "enabled", havingValue = "true")
public class AgentGuardMcpAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public McpToolGuard mcpToolGuard(
      ToolGuard guard,
      PrincipalResolver principals,
      ObjectProvider<JsonMapper> mappers,
      GuardCoverage coverage) {
    return new McpToolGuard(
        guard, principals, mappers.getIfAvailable(() -> JsonMapper.builder().build()), coverage);
  }

  @Bean
  public static McpToolSpecificationGuardBeanPostProcessor
      mcpToolSpecificationGuardBeanPostProcessor(BeanFactory beanFactory) {
    return new McpToolSpecificationGuardBeanPostProcessor(beanFactory);
  }
}

package com.housedevinci.agentguard.ai;

import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.autoconfigure.GuardCoverage;
import com.housedevinci.agentguard.security.PrincipalResolver;
import io.micrometer.observation.ObservationRegistry;
import org.springframework.ai.model.tool.DefaultToolCallingManager;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.execution.ToolExecutionExceptionProcessor;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Spring AI tool-calling integration. Every {@code ToolCallback} / provider / resolver bean is
 * wrapped, and the {@link ToolCallingManager} bean (the one ChatModels execute tools through) is
 * wrapped too, so inline tools ({@code .tools(obj)}, {@code ToolCallbacks.from}) are guarded.
 */
@AutoConfiguration(
    after = AgentGuardAutoConfiguration.class,
    beforeName = "org.springframework.ai.model.tool.autoconfigure.ToolCallingAutoConfiguration")
@ConditionalOnClass(ToolCallback.class)
@ConditionalOnProperty(prefix = "agentguard", name = "enabled", havingValue = "true")
public class AgentGuardSpringAiAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AgentGuard agentGuard(
      ToolGuard guard, PrincipalResolver principals, GuardCoverage coverage) {
    return new AgentGuard(guard, principals, coverage);
  }

  /**
   * A {@code ToolCallingManager} exists in every application that executes tools; when Spring AI's
   * own auto-configuration does not provide one, this guarded default does. Either way the bean
   * post-processor wraps whichever instance ends up in the context.
   */
  @Bean
  @ConditionalOnMissingBean(ToolCallingManager.class)
  public ToolCallingManager agentGuardToolCallingManager(
      AgentGuard agentGuard,
      ObjectProvider<ObservationRegistry> observationRegistry,
      ObjectProvider<ToolCallbackResolver> resolver,
      ObjectProvider<ToolExecutionExceptionProcessor> exceptionProcessor) {
    var builder = DefaultToolCallingManager.builder();
    observationRegistry.ifAvailable(builder::observationRegistry);
    resolver.ifAvailable(builder::toolCallbackResolver);
    exceptionProcessor.ifAvailable(builder::toolExecutionExceptionProcessor);
    return agentGuard.guard(builder.build());
  }

  @Bean
  public static ToolCallbackGuardBeanPostProcessor toolCallbackGuardBeanPostProcessor(
      BeanFactory beanFactory) {
    return new ToolCallbackGuardBeanPostProcessor(beanFactory);
  }
}

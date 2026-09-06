package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.domain.PolicyRule;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Set;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * Finds {@code @ToolPolicy} on bean methods and registers the rule under the tool name: the {@code
 * name} of {@code @Tool} / {@code @McpTool} when set, else the method name.
 */
public final class ToolPolicyAnnotationScanner implements BeanPostProcessor {

  private static final String SPRING_AI_TOOL = "org.springframework.ai.tool.annotation.Tool";
  private static final String MCP_TOOL = "org.springframework.ai.mcp.annotation.McpTool";

  private final ToolPolicyRegistry registry;
  private final GuardCoverage coverage;
  private final Class<? extends Annotation> springAiTool;
  private final Class<? extends Annotation> mcpTool;

  public ToolPolicyAnnotationScanner(ToolPolicyRegistry registry) {
    this(registry, new GuardCoverage());
  }

  public ToolPolicyAnnotationScanner(ToolPolicyRegistry registry, GuardCoverage coverage) {
    this.registry = registry;
    this.coverage = coverage;
    this.springAiTool = load(SPRING_AI_TOOL);
    this.mcpTool = load(MCP_TOOL);
  }

  @SuppressWarnings("unchecked")
  private static Class<? extends Annotation> load(String name) {
    var cl = ToolPolicyAnnotationScanner.class.getClassLoader();
    if (!ClassUtils.isPresent(name, cl)) {
      return null;
    }
    try {
      return (Class<? extends Annotation>) ClassUtils.forName(name, cl);
    } catch (ClassNotFoundException e) {
      return null;
    }
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) {
    Class<?> target = AopUtils.getTargetClass(bean);
    ReflectionUtils.doWithMethods(
        target,
        m -> {
          ToolPolicy policy = AnnotatedElementUtils.findMergedAnnotation(m, ToolPolicy.class);
          if (policy != null) {
            String name = toolName(m);
            registry.register(name, rule(policy));
            coverage.declared(name, declared(m));
          }
        },
        ReflectionUtils.USER_DECLARED_METHODS);
    return bean;
  }

  static PolicyRule rule(ToolPolicy p) {
    return new PolicyRule(
        Set.of(p.roles()), Set.of(p.scopes()), Set.of(p.tenants()), p.sideEffect());
  }

  GuardCoverage.Declared declared(Method m) {
    if (springAiTool != null && AnnotationUtils.findAnnotation(m, springAiTool) != null) {
      return GuardCoverage.Declared.TOOL;
    }
    if (mcpTool != null && AnnotationUtils.findAnnotation(m, mcpTool) != null) {
      return GuardCoverage.Declared.MCP_TOOL;
    }
    return GuardCoverage.Declared.PLAIN_METHOD;
  }

  String toolName(Method m) {
    String name = nameFrom(m, springAiTool);
    if (name == null) {
      name = nameFrom(m, mcpTool);
    }
    return name == null ? m.getName() : name;
  }

  private static String nameFrom(Method m, Class<? extends Annotation> type) {
    if (type == null) {
      return null;
    }
    Annotation a = AnnotationUtils.findAnnotation(m, type);
    if (a == null) {
      return null;
    }
    Object value = AnnotationUtils.getValue(a, "name");
    return value instanceof String s && !s.isBlank() ? s : null;
  }
}

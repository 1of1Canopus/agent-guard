package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.jdbc.JdbcBudgetStore;
import com.housedevinci.agentguard.adapter.jdbc.JdbcDecisionStore;
import com.housedevinci.agentguard.adapter.jdbc.JdbcSupport;
import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.adapter.memory.InMemoryBudgetStore;
import com.housedevinci.agentguard.adapter.memory.InMemoryDecisionStore;
import com.housedevinci.agentguard.adapter.notify.CompositeNotifier;
import com.housedevinci.agentguard.adapter.notify.LoggingNotifier;
import com.housedevinci.agentguard.adapter.notify.WebhookNotifier;
import com.housedevinci.agentguard.adapter.redis.JedisBudgetStore;
import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.application.AuditRecorder;
import com.housedevinci.agentguard.application.BudgetEnforcer;
import com.housedevinci.agentguard.application.DecisionResumer;
import com.housedevinci.agentguard.application.PolicyLookup;
import com.housedevinci.agentguard.application.ToolExecutorRegistry;
import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.domain.ArgumentRedactor;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.BudgetLimit;
import com.housedevinci.agentguard.domain.BudgetStore;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.Notifier;
import com.housedevinci.agentguard.domain.ToolPolicyEvaluator;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import com.housedevinci.agentguard.security.PrincipalResolver;
import com.housedevinci.agentguard.security.SecurityContextPrincipalResolver;
import com.housedevinci.agentguard.security.TenantResolver;
import com.housedevinci.agentguard.security.ToolPolicyAuthorizationManager;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import redis.clients.jedis.JedisPooled;
import redis.clients.jedis.UnifiedJedis;

/**
 * Wires the free core. Active only with {@code agentguard.enabled=true}. Every port has a
 * {@code @ConditionalOnMissingBean} so an application can replace any piece.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "agentguard", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(AgentGuardProperties.class)
public class AgentGuardAutoConfiguration {

  private static final Logger log = LoggerFactory.getLogger(AgentGuardAutoConfiguration.class);

  @Bean
  @ConditionalOnMissingBean(name = "agentGuardClock")
  public Clock agentGuardClock() {
    return Clock.systemUTC();
  }

  @Bean
  @ConditionalOnMissingBean
  public ToolPolicyRegistry toolPolicyRegistry() {
    return new ToolPolicyRegistry();
  }

  @Bean
  public static ToolPolicyAnnotationScanner toolPolicyAnnotationScanner(ToolPolicyRegistry registry) {
    return new ToolPolicyAnnotationScanner(registry);
  }

  @Bean
  @ConditionalOnMissingBean
  public ToolPolicyEvaluator toolPolicyEvaluator(AgentGuardProperties props) {
    return new ToolPolicyEvaluator(props.getPolicy().getApprovalRequiredFor());
  }

  @Bean
  @ConditionalOnMissingBean
  public PolicyLookup policyLookup(ToolPolicyRegistry registry, AgentGuardProperties props) {
    return new PolicyLookup(registry, props.getPolicy().getUnregisteredTools());
  }

  @Bean
  @ConditionalOnMissingBean
  public ArgumentRedactor argumentRedactor(AgentGuardProperties props) {
    return new ArgumentRedactor(
        props.getRedaction().getSensitiveKeys(), props.getRedaction().getMaxPreviewLength());
  }

  @Bean
  @ConditionalOnMissingBean
  public ToolExecutorRegistry toolExecutorRegistry() {
    return new ToolExecutorRegistry();
  }

  // ---- stores -------------------------------------------------------------------------------

  @Bean
  @ConditionalOnMissingBean
  public DecisionStore decisionStore(AgentGuardProperties props, ObjectProvider<DataSource> dataSources) {
    return switch (props.getStore()) {
      case MEMORY -> {
        log.warn("agentguard.store=MEMORY: decisions and audit are not durable. Use JDBC in production.");
        yield new InMemoryDecisionStore();
      }
      case JDBC -> new JdbcDecisionStore(jdbc(props, dataSources));
    };
  }

  @Bean
  @ConditionalOnMissingBean(AuditSink.class)
  public AuditSink auditSink(AgentGuardProperties props, ObjectProvider<DataSource> dataSources) {
    return switch (props.getStore()) {
      case MEMORY -> new InMemoryAuditSink();
      case JDBC -> new JdbcAuditSink(jdbc(props, dataSources));
    };
  }

  @Bean
  @ConditionalOnMissingBean(AuditReader.class)
  public AuditReader auditReader(AuditSink sink) {
    if (sink instanceof AuditReader reader) {
      return reader;
    }
    throw new AgentGuardConfigurationException(
        "The AuditSink bean does not implement AuditReader; also provide an AuditReader bean");
  }

  @Bean
  @ConditionalOnMissingBean
  public BudgetStore budgetStore(
      AgentGuardProperties props, ObjectProvider<DataSource> dataSources, Clock agentGuardClock) {
    var type = props.getBudgets().getStore();
    if (type == AgentGuardProperties.BudgetStoreType.DEFAULT) {
      type =
          props.getStore() == AgentGuardProperties.StoreType.JDBC
              ? AgentGuardProperties.BudgetStoreType.JDBC
              : AgentGuardProperties.BudgetStoreType.MEMORY;
    }
    return switch (type) {
      case MEMORY -> new InMemoryBudgetStore(agentGuardClock);
      case JDBC -> new JdbcBudgetStore(jdbc(props, dataSources), agentGuardClock);
      case REDIS -> {
        if (props.getRedis().getUri() == null) {
          throw new AgentGuardConfigurationException(
              "agentguard.redis.uri is required when agentguard.budgets.store=REDIS");
        }
        UnifiedJedis jedis = new JedisPooled(props.getRedis().getUri().toString());
        yield new JedisBudgetStore(jedis);
      }
      case DEFAULT -> throw new IllegalStateException("unreachable");
    };
  }

  private static DataSource jdbc(AgentGuardProperties props, ObjectProvider<DataSource> dataSources) {
    DataSource ds = dataSources.getIfAvailable();
    if (ds == null) {
      throw new AgentGuardConfigurationException(
          "agentguard.store=JDBC requires a DataSource bean when agentguard.enabled=true "
              + "(add spring-boot-starter-jdbc + spring.datasource.*, or set agentguard.store=MEMORY for development)");
    }
    if (props.getJdbc().isInitializeSchema()) {
      JdbcSupport.initializeSchema(ds);
    }
    return ds;
  }

  // ---- notifiers ----------------------------------------------------------------------------

  @Bean
  @ConditionalOnMissingBean
  public Notifier approvalNotifier(AgentGuardProperties props) {
    var n = props.getApproval().getNotifier();
    List<Notifier> delegates = new ArrayList<>();
    if (n.isLogEnabled()) {
      delegates.add(new LoggingNotifier());
    }
    if (n.getWebhookUrl() != null) {
      delegates.add(new WebhookNotifier(n.getWebhookUrl(), n.getWebhookSecret(), n.getWebhookTimeout()));
    }
    if (delegates.isEmpty()) {
      log.warn("agentguard: no approval notifier configured; parked calls are only visible through the store");
    }
    return new CompositeNotifier(delegates);
  }

  // ---- application services -----------------------------------------------------------------

  @Bean
  @ConditionalOnMissingBean
  public AuditRecorder auditRecorder(AuditSink sink, Clock agentGuardClock) {
    return new AuditRecorder(sink, agentGuardClock);
  }

  @Bean
  @ConditionalOnMissingBean
  public AuditChainVerifier auditChainVerifier(AuditReader reader) {
    return new AuditChainVerifier(reader);
  }

  @Bean
  @ConditionalOnMissingBean
  public BudgetEnforcer budgetEnforcer(AgentGuardProperties props, BudgetStore store, Clock agentGuardClock) {
    List<BudgetLimit> limits =
        props.getBudgets().getLimits().stream()
            .map(l -> new BudgetLimit(l.getScope(), l.getKind(), l.getWindow(), l.getLimit()))
            .toList();
    return new BudgetEnforcer(limits, store, agentGuardClock);
  }

  @Bean
  @ConditionalOnMissingBean
  public DecisionResumer decisionResumer(
      DecisionStore store, ToolExecutorRegistry executors, BudgetEnforcer budgets, AuditRecorder audit, Clock agentGuardClock) {
    return new DecisionResumer(store, executors, budgets, audit, agentGuardClock);
  }

  @Bean
  @ConditionalOnMissingBean
  public ApprovalService approvalService(
      DecisionStore store, Notifier notifier, DecisionResumer resumer, AuditRecorder audit,
      Clock agentGuardClock, AgentGuardProperties props) {
    return new ApprovalService(store, notifier, resumer, audit, agentGuardClock, props.getApproval().getTtl());
  }

  @Bean
  @ConditionalOnMissingBean
  public ToolGuard toolGuard(
      PolicyLookup policies, ToolPolicyEvaluator evaluator, BudgetEnforcer budgets, ApprovalService approvals,
      DecisionResumer resumer, DecisionStore decisions, ToolExecutorRegistry executors, AuditRecorder audit,
      ArgumentRedactor redactor, Clock agentGuardClock) {
    return new ToolGuard(policies, evaluator, budgets, approvals, resumer, decisions, executors, audit, redactor, agentGuardClock);
  }

  // ---- principal ----------------------------------------------------------------------------

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(SecurityContextHolder.class)
  static class SecurityPrincipalConfiguration {

    @Bean
    @ConditionalOnMissingBean
    TenantResolver tenantResolver() {
      return auth -> Optional.empty();
    }

    @Bean
    @ConditionalOnMissingBean
    PrincipalResolver principalResolver(TenantResolver tenantResolver) {
      return new SecurityContextPrincipalResolver(tenantResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    ToolPolicyAuthorizationManager toolPolicyAuthorizationManager(
        PolicyLookup policies, ToolPolicyEvaluator evaluator, TenantResolver tenantResolver) {
      return new ToolPolicyAuthorizationManager(policies, evaluator, tenantResolver);
    }
  }

  @Bean
  @ConditionalOnMissingBean(PrincipalResolver.class)
  public PrincipalResolver anonymousPrincipalResolver() {
    log.warn("agentguard: Spring Security not on the classpath; every caller is 'anonymous'. Provide a PrincipalResolver bean.");
    return com.housedevinci.agentguard.domain.Principal::anonymous;
  }
}

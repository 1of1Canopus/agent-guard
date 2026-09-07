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
import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.application.AuditChainVerifier;
import com.housedevinci.agentguard.application.AuditRecorder;
import com.housedevinci.agentguard.application.BudgetEnforcer;
import com.housedevinci.agentguard.application.DecisionResumer;
import com.housedevinci.agentguard.application.GuardOptions;
import com.housedevinci.agentguard.application.MissingSubjectPolicy;
import com.housedevinci.agentguard.application.PolicyLookup;
import com.housedevinci.agentguard.application.PrincipalRefresher;
import com.housedevinci.agentguard.application.ResumeContextProvider;
import com.housedevinci.agentguard.application.ToolExecutorRegistry;
import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.domain.ArgumentRedactor;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.BudgetLimit;
import com.housedevinci.agentguard.domain.BudgetStore;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.Notifier;
import com.housedevinci.agentguard.domain.ToolPolicyEvaluator;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import com.housedevinci.agentguard.security.NoTenantResolver;
import com.housedevinci.agentguard.security.PrincipalResolver;
import com.housedevinci.agentguard.security.SecurityContextPrincipalResolver;
import com.housedevinci.agentguard.security.TenantResolver;
import com.housedevinci.agentguard.security.ToolPolicyAuthorizationManager;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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
  @ConditionalOnMissingBean
  public GuardCoverage guardCoverage() {
    return new GuardCoverage();
  }

  @Bean
  public static ToolPolicyAnnotationScanner toolPolicyAnnotationScanner(
      ToolPolicyRegistry registry, GuardCoverage coverage) {
    return new ToolPolicyAnnotationScanner(registry, coverage);
  }

  @Bean
  public AgentGuardStartupCheck agentGuardStartupCheck(
      GuardCoverage coverage, AgentGuardProperties props) {
    return new AgentGuardStartupCheck(coverage, props);
  }

  @Bean
  @ConditionalOnMissingBean
  public PrincipalRefresher principalRefresher() {
    return PrincipalRefresher.identity();
  }

  @Bean
  @ConditionalOnMissingBean
  public AuditChain auditChain(AgentGuardProperties props) {
    String secret = props.getAudit().getHmacSecret();
    if (secret != null && !secret.isBlank() && props.getAudit().isUnkeyed()) {
      throw new AgentGuardConfigurationException(
          "agentguard.audit.unkeyed=true contradicts agentguard.audit.hmac-secret (set): a trail is"
              + " keyed from row 1 or unkeyed forever, so both cannot be asked for at once. Remove"
              + " agentguard.audit.hmac-secret to run unkeyed, or remove agentguard.audit.unkeyed to"
              + " run keyed.");
    }
    if (secret == null || secret.isBlank()) {
      if (!props.getAudit().isUnkeyed()) {
        throw new AgentGuardConfigurationException(
            "agentguard.audit.hmac-secret is required (a trail is keyed from row 1 or unkeyed"
                + " forever; unkeyed-by-accident is the wrong default for an audit trail). Set it"
                + " from an environment variable — generate one with `openssl rand -base64 32` — or,"
                + " for local development only, set agentguard.audit.unkeyed=true to start unkeyed"
                + " (a database writer can then rewrite the trail undetected).");
      }
      log.warn(
          "agentguard.audit.unkeyed=true: the audit trail is unkeyed; a database writer can rewrite"
              + " it undetected. Local development only; set agentguard.audit.hmac-secret in"
              + " production.");
      return AuditChain.unkeyed();
    }
    byte[] key = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    if (key.length < AuditChain.MIN_KEY_BYTES) {
      throw new AgentGuardConfigurationException(
          "agentguard.audit.hmac-secret must be at least " + AuditChain.MIN_KEY_BYTES + " bytes");
    }
    return AuditChain.keyed(key, props.getAudit().getHmacKeyId());
  }

  /**
   * Every key the verifier must accept: the current appending key ({@code hmac-secret}/{@code
   * hmac-key-id}) plus every retired one in {@code agentguard.audit.hmac-keys}, so historical rows
   * signed under a rotated-away id still verify.
   */
  @Bean
  @ConditionalOnMissingBean
  public java.util.Map<String, byte[]> auditKeyring(
      AgentGuardProperties props, AuditChain auditChain) {
    var keyring = new java.util.LinkedHashMap<String, byte[]>();
    if (auditChain.isKeyed()) {
      keyring.put(
          auditChain.keyId(),
          props.getAudit().getHmacSecret().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    props
        .getAudit()
        .getHmacKeys()
        .forEach(
            (id, secret) -> {
              byte[] bytes = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
              if (bytes.length < AuditChain.MIN_KEY_BYTES) {
                throw new AgentGuardConfigurationException(
                    "agentguard.audit.hmac-keys."
                        + id
                        + " must be at least "
                        + AuditChain.MIN_KEY_BYTES
                        + " bytes");
              }
              if (auditChain.isKeyed()
                  && id.equals(auditChain.keyId())
                  && !java.util.Arrays.equals(bytes, keyring.get(id))) {
                throw new AgentGuardConfigurationException(
                    "agentguard.audit.hmac-keys."
                        + id
                        + " reuses the appending key id (agentguard.audit.hmac-key-id="
                        + id
                        + ") with a different secret than agentguard.audit.hmac-secret. Give the"
                        + " new key its own id instead of retiring it under the id still in use.");
              }
              keyring.put(id, bytes);
            });
    return java.util.Map.copyOf(keyring);
  }

  @Bean
  @ConditionalOnMissingBean
  public ResumeContextProvider resumeContextProvider() {
    if (org.springframework.util.ClassUtils.isPresent(
        "org.springframework.security.core.context.SecurityContextHolder", null)) {
      return new com.housedevinci.agentguard.security.SecurityContextResumeContextProvider();
    }
    return ResumeContextProvider.none();
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
  public DecisionStore decisionStore(
      AgentGuardProperties props, ObjectProvider<DataSource> dataSources) {
    return switch (props.getStore()) {
      case MEMORY -> {
        log.warn(
            "agentguard.store=MEMORY: decisions and audit are not durable. Use JDBC in production.");
        yield new InMemoryDecisionStore();
      }
      case JDBC -> new JdbcDecisionStore(jdbc(props, dataSources));
    };
  }

  @Bean
  @ConditionalOnMissingBean(AuditSink.class)
  @ConditionalOnProperty(prefix = "agentguard", name = "store", havingValue = "MEMORY")
  public InMemoryAuditSink inMemoryAuditSink(AuditChain chain) {
    return new InMemoryAuditSink(chain);
  }

  @Bean
  @ConditionalOnMissingBean(AuditSink.class)
  @ConditionalOnProperty(
      prefix = "agentguard",
      name = "store",
      havingValue = "JDBC",
      matchIfMissing = true)
  public JdbcAuditSink jdbcAuditSink(
      AgentGuardProperties props, ObjectProvider<DataSource> dataSources) {
    return new JdbcAuditSink(jdbc(props, dataSources));
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
        if (!org.springframework.util.ClassUtils.isPresent(
            "redis.clients.jedis.UnifiedJedis", null)) {
          throw new AgentGuardConfigurationException(
              "agentguard.budgets.store=REDIS requires redis.clients:jedis on the classpath");
        }
        yield JedisBudgetStoreFactory.create(props.getRedis().getUri(), props.getRedis().getPool());
      }
      case DEFAULT -> throw new IllegalStateException("unreachable");
    };
  }

  /** DataSources whose schema step already ran in this JVM (L10: once, not per bean). */
  private static final Set<Integer> SCHEMA_DONE = ConcurrentHashMap.newKeySet();

  private static DataSource jdbc(
      AgentGuardProperties props, ObjectProvider<DataSource> dataSources) {
    DataSource ds = dataSources.getIfAvailable();
    if (ds == null) {
      throw new AgentGuardConfigurationException(
          "agentguard.store=JDBC requires a DataSource bean when agentguard.enabled=true, but no"
              + " DataSource found (add spring-boot-starter-jdbc + spring.datasource.*). For a local"
              + " trial set agentguard.store=memory - not for production.");
    }
    if (props.getJdbc().isInitializeSchema() && SCHEMA_DONE.add(System.identityHashCode(ds))) {
      JdbcSupport.initializeSchema(ds);
      log.info("agentguard: schema step ran (agentguard.jdbc.initialize-schema=true)");
      try {
        if (JdbcSupport.runtimeRoleOwnsAuditTable(ds)) {
          log.warn(
              "agentguard: the runtime database role owns agentguard_audit and can disable its"
                  + " append-only triggers; use a separate owner role for the schema and a runtime role"
                  + " with INSERT/SELECT only (docs, \"Database roles\")");
        }
      } catch (RuntimeException e) {
        log.debug("agentguard: could not determine the audit table owner: {}", e.toString());
      }
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
      try {
        delegates.add(
            new WebhookNotifier(
                n.getWebhookUrl(),
                n.getWebhookSecret(),
                n.getWebhookTimeout(),
                n.isWebhookAllowInsecure(),
                n.isWebhookLegacyToken()));
      } catch (IllegalArgumentException e) {
        throw new AgentGuardConfigurationException(e.getMessage());
      }
    }
    if (delegates.isEmpty()) {
      log.warn(
          "agentguard: no approval notifier configured; parked calls are only visible through the store");
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
  public AuditChainVerifier auditChainVerifier(
      AuditReader reader, java.util.Map<String, byte[]> auditKeyring) {
    return AuditChainVerifier.of(reader, auditKeyring);
  }

  @Bean
  @ConditionalOnMissingBean
  public BudgetEnforcer budgetEnforcer(
      AgentGuardProperties props,
      BudgetStore store,
      Clock agentGuardClock,
      ObjectProvider<TenantResolver> tenantResolver) {
    List<BudgetLimit> limits =
        props.getBudgets().getLimits().stream()
            .map(l -> new BudgetLimit(l.getScope(), l.getKind(), l.getWindow(), l.getLimit()))
            .toList();
    for (int i = 0; i < limits.size(); i++) {
      var l = limits.get(i);
      boolean ok =
          switch (l.kind()) {
            case STEPS -> l.scope() == com.housedevinci.agentguard.domain.BudgetScope.CONVERSATION;
            case TOOL_CALLS ->
                l.scope() != com.housedevinci.agentguard.domain.BudgetScope.CONVERSATION;
            case TOKENS -> true;
          };
      if (!ok) {
        throw new AgentGuardConfigurationException(
            "agentguard.budgets.limits["
                + i
                + "]: kind="
                + l.kind()
                + " is not valid with scope="
                + l.scope()
                + " (STEPS needs CONVERSATION; TOOL_CALLS needs PRINCIPAL or TENANT)");
      }
    }
    boolean conversationLimit =
        limits.stream()
            .anyMatch(
                l -> l.scope() == com.housedevinci.agentguard.domain.BudgetScope.CONVERSATION);
    boolean principalLimit =
        limits.stream()
            .anyMatch(l -> l.scope() == com.housedevinci.agentguard.domain.BudgetScope.PRINCIPAL);
    if (conversationLimit && !principalLimit) {
      log.warn(
          "agentguard.budgets.limits has a CONVERSATION limit but no PRINCIPAL limit: a conversation is"
              + " an MCP session and a client can open a new one; pair it with a PRINCIPAL limit");
    }
    boolean tenantLimits =
        limits.stream()
            .anyMatch(l -> l.scope() == com.housedevinci.agentguard.domain.BudgetScope.TENANT);
    if (tenantLimits && tenantResolver.getIfAvailable() instanceof NoTenantResolver) {
      log.warn(
          "agentguard.budgets.limits contains a TENANT limit but no TenantResolver bean is"
              + " configured: no call carries a tenant, so the limit {} every call"
              + " (agentguard.budgets.missing-subject)",
          props.isStrict() ? "denies" : "is skipped for");
    }
    var missing =
        switch (props.getBudgets().getMissingSubject()) {
          case DEFAULT -> props.isStrict() ? MissingSubjectPolicy.DENY : MissingSubjectPolicy.SKIP;
          case DENY -> MissingSubjectPolicy.DENY;
          case FALLBACK_TO_PRINCIPAL -> MissingSubjectPolicy.FALLBACK_TO_PRINCIPAL;
          case SKIP -> MissingSubjectPolicy.SKIP;
        };
    return new BudgetEnforcer(limits, store, agentGuardClock, missing);
  }

  @Bean
  @ConditionalOnMissingBean
  public DecisionResumer decisionResumer(
      DecisionStore store,
      ToolExecutorRegistry executors,
      AuditRecorder audit,
      ResumeContextProvider resumeContext,
      PolicyLookup policies,
      ToolPolicyEvaluator evaluator,
      PrincipalRefresher refresher,
      AgentGuardProperties props,
      Clock agentGuardClock) {
    return new DecisionResumer(
        store,
        executors,
        audit,
        resumeContext,
        policies,
        evaluator,
        refresher,
        props.getErrors().isIncludeToolMessage(),
        agentGuardClock);
  }

  @Bean
  @ConditionalOnMissingBean
  public ApprovalService approvalService(
      DecisionStore store,
      Notifier notifier,
      DecisionResumer resumer,
      AuditRecorder audit,
      Clock agentGuardClock,
      AgentGuardProperties props) {
    return new ApprovalService(
        store,
        notifier,
        resumer,
        audit,
        agentGuardClock,
        props.getApproval().getTtl(),
        props.getApproval().isAllowSelfApproval());
  }

  @Bean
  @ConditionalOnMissingBean
  public ToolGuard toolGuard(
      PolicyLookup policies,
      ToolPolicyEvaluator evaluator,
      BudgetEnforcer budgets,
      ApprovalService approvals,
      DecisionResumer resumer,
      DecisionStore decisions,
      ToolExecutorRegistry executors,
      AuditRecorder audit,
      ArgumentRedactor redactor,
      AgentGuardProperties props,
      Clock agentGuardClock) {
    var limits =
        new GuardOptions(
            props.getApproval().getMaxPendingPerPrincipal(),
            props.getApproval().getMaxArgumentBytes(),
            props.getApproval().effectiveReplayWindow(),
            props.getErrors().isIncludeToolMessage());
    return new ToolGuard(
        policies,
        evaluator,
        budgets,
        approvals,
        resumer,
        decisions,
        executors,
        audit,
        redactor,
        limits,
        agentGuardClock);
  }

  // ---- principal ----------------------------------------------------------------------------

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "org.springframework.security.core.context.SecurityContextHolder")
  static class SecurityPrincipalConfiguration {

    @Bean
    @ConditionalOnMissingBean
    TenantResolver tenantResolver() {
      return new NoTenantResolver();
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
    log.warn(
        "agentguard: Spring Security not on the classpath; every caller is 'anonymous'. Provide a PrincipalResolver bean.");
    return com.housedevinci.agentguard.domain.Principal::anonymous;
  }
}

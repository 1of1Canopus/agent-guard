package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;

/**
 * Startup check that every audit sink bean of the context matches the configured audit mode
 * (B-SMP-1). It refuses with {@link ErrorCodes#AUDIT_SINK_UNKEYED} when a sink is unkeyed and
 * {@code agentguard.audit.hmac-secret} is set, or when a sink is unkeyed and {@code
 * agentguard.audit.unkeyed=true} is not set. No property turns the refusal into a warning.
 *
 * <p>When {@code agentguard.audit.unkeyed=true}, it WARNs at every startup.
 *
 * <ul>
 *   <li>Sinks it can see into: {@link JdbcAuditSink} and {@link InMemoryAuditSink}, also behind a
 *       Spring AOP proxy with a singleton target.
 *   <li>Any other {@link AuditSink} implementation: it cannot read the sink's mode, so it starts
 *       and WARNs at every startup, naming the bean.
 *   <li>Lifecycle: like {@link JdbcAuditSinkDataSourceCheck}. Before the singletons exist it only
 *       records what it sees; once they exist it creates every {@code AuditSink} bean (lazy ones
 *       too) and checks them. A sink created later (prototype scope) is checked as it is created.
 * </ul>
 *
 * <p>Not covered: a sink built inside another bean and never exposed as a bean.
 */
final class AuditSinkKeyCheck
    implements BeanPostProcessor, PriorityOrdered, SmartInitializingSingleton, BeanFactoryAware {

  private static final Logger log = LoggerFactory.getLogger(AuditSinkKeyCheck.class);

  /** What the check knows about one sink bean. */
  private enum Mode {
    KEYED,
    UNKEYED,
    UNKNOWN
  }

  private final ReentrantLock lock = new ReentrantLock();

  /**
   * Every instance seen per bean name: the raw one before initialization, the wrapped one after.
   */
  private final Map<String, List<Object>> recorded = new LinkedHashMap<>();

  private boolean started;
  private ListableBeanFactory beanFactory;

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

  @Override
  public void setBeanFactory(BeanFactory beanFactory) {
    if (!(beanFactory instanceof ListableBeanFactory listable)) {
      throw new AgentGuardConfigurationException(
          "agentguard: the audit key check needs a ListableBeanFactory, got "
              + beanFactory.getClass().getName());
    }
    this.beanFactory = listable;
  }

  @Override
  public Object postProcessBeforeInitialization(Object bean, String beanName) {
    see(bean, beanName);
    return bean;
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) {
    see(bean, beanName);
    return bean;
  }

  private void see(Object bean, String beanName) {
    if (!(bean instanceof AuditSink)) {
      return;
    }
    lock.lock();
    try {
      if (!started) {
        add(recorded, beanName, bean);
        return;
      }
    } finally {
      lock.unlock();
    }
    check(beanName, List.of(bean), audit());
  }

  @Override
  public void afterSingletonsInstantiated() {
    // creates lazy sinks now, so they are checked at startup and not at their first use
    Map<String, AuditSink> sinks = beanFactory.getBeansOfType(AuditSink.class, false, true);
    Map<String, List<Object>> toCheck = new LinkedHashMap<>();
    lock.lock();
    try {
      started = true;
      recorded.forEach((name, seen) -> seen.forEach(b -> add(toCheck, name, b)));
      recorded.clear();
    } finally {
      lock.unlock();
    }
    sinks.forEach((name, b) -> add(toCheck, name, b));
    AgentGuardProperties.Audit audit = audit();
    if (audit.isUnkeyed()) {
      log.warn(
          "agentguard.audit.unkeyed=true: the audit trail is unkeyed; a database writer can rewrite"
              + " it undetected. Local development only; set agentguard.audit.hmac-secret in"
              + " production.");
    }
    toCheck.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(e -> check(e.getKey(), e.getValue(), audit));
  }

  /** Adds {@code bean} under {@code name} unless that very instance is already there. */
  private static void add(Map<String, List<Object>> into, String name, Object bean) {
    List<Object> seen = into.computeIfAbsent(name, n -> new ArrayList<>());
    if (seen.stream().noneMatch(b -> b == bean)) {
      seen.add(bean);
    }
  }

  private AgentGuardProperties.Audit audit() {
    return beanFactory.getBean(AgentGuardProperties.class).getAudit();
  }

  private static boolean secretSet(AgentGuardProperties.Audit audit) {
    String secret = audit.getHmacSecret();
    return secret != null && !secret.isBlank();
  }

  private static Mode mode(Object bean) {
    Object target = bean;
    for (int depth = 0; depth < 8; depth++) {
      switch (target) {
        case JdbcAuditSink s -> {
          return s.isKeyed() ? Mode.KEYED : Mode.UNKEYED;
        }
        case InMemoryAuditSink s -> {
          return s.isKeyed() ? Mode.KEYED : Mode.UNKEYED;
        }
        default -> {
          Optional<Object> inner = Optional.ofNullable(AopProxyUtils.getSingletonTarget(target));
          if (inner.isEmpty()) {
            return Mode.UNKNOWN;
          }
          target = inner.get();
        }
      }
    }
    return Mode.UNKNOWN;
  }

  /**
   * One bean name, every instance seen for it. Unkeyed on any instance wins (a wrapper the starter
   * cannot see into must not hide the unkeyed sink inside it); keyed on any instance needs no WARN.
   */
  private static void check(String beanName, List<Object> seen, AgentGuardProperties.Audit audit) {
    Optional<Object> unkeyed = seen.stream().filter(b -> mode(b) == Mode.UNKEYED).findFirst();
    if (unkeyed.isPresent()) {
      String what =
          "the audit sink bean '" + beanName + "' (" + unkeyed.get().getClass().getName() + ")";
      if (secretSet(audit)) {
        throw new AgentGuardException(
            ErrorCodes.AUDIT_SINK_UNKEYED,
            "agentguard.audit.hmac-secret is set but "
                + what
                + " is unkeyed: its rows would carry key_id=none and the verifier would report"
                + " INTACT_UNKEYED. Build it with the AuditChain bean, for example new"
                + " JdbcAuditSink(dataSource, auditChain), or remove the bean and let the"
                + " starter build it.");
      }
      if (!audit.isUnkeyed()) {
        throw new AgentGuardException(
            ErrorCodes.AUDIT_SINK_UNKEYED,
            what
                + " is unkeyed but agentguard.audit.unkeyed=true is not set. Set"
                + " agentguard.audit.hmac-secret and build the sink with the AuditChain bean,"
                + " or, for local development only, set agentguard.audit.unkeyed=true.");
      }
      return;
    }
    if (seen.stream().noneMatch(b -> mode(b) == Mode.KEYED)) {
      log.warn(
          "agentguard: the audit sink bean '{}' ({}) is not a sink the starter knows, so it"
              + " cannot verify that it is keyed. Make sure it signs rows with the AuditChain"
              + " bean; the verifier reports INTACT_UNKEYED on an unkeyed trail.",
          beanName,
          seen.get(seen.size() - 1).getClass().getName());
    }
  }
}

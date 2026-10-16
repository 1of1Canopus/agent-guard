package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.memory.InMemoryAuditSink;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
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
 * (B-SMP-1). It refuses with {@link ErrorCodes#AUDIT_SINK_UNKEYED}:
 *
 * <ul>
 *   <li>a sink that is unkeyed while {@code agentguard.audit.hmac-secret} is set;
 *   <li>a sink that is unkeyed while {@code agentguard.audit.unkeyed=true} is not set;
 *   <li>a sink whose mode it cannot read (a class other than {@link JdbcAuditSink} and {@link
 *       InMemoryAuditSink}, or a scoped proxy), unless its bean name is listed in {@code
 *       agentguard.audit.unverified-sinks}. A listed sink starts with a WARN at every startup.
 * </ul>
 *
 * <p>It also refuses {@code agentguard.audit.hmac-secret} together with {@code
 * agentguard.audit.unkeyed=true}, whoever built the {@code AuditChain}. No property turns a refusal
 * into a warning. Under {@code agentguard.audit.unkeyed=true} it WARNs at every startup.
 *
 * <p>When. A sink whose mode it can read (also behind a Spring AOP proxy with a singleton target)
 * is decided in the post-processor hooks, before and after initialization, so an unkeyed sink is
 * refused before any other bean can write a row with it (B-KS-1). Seeing the raw instance in the
 * before-hook means a wrapper added later cannot hide it. A sink it cannot read is decided once the
 * singletons exist; that pass also creates every lazy {@code AuditSink} bean. A sink created after
 * startup (prototype scope) is decided as it is created.
 *
 * <p>Not covered: a sink built inside another bean and never exposed as a bean, and a sink created
 * before this post-processor is registered (a dependency of another priority-ordered
 * post-processor), which is decided only at the end of startup.
 */
final class AuditSinkKeyCheck
    implements BeanPostProcessor, PriorityOrdered, SmartInitializingSingleton, BeanFactoryAware {

  private static final Logger log = LoggerFactory.getLogger(AuditSinkKeyCheck.class);

  /** What the check knows about one sink instance. */
  private enum Mode {
    KEYED,
    UNKEYED,
    UNKNOWN
  }

  private final ReentrantLock lock = new ReentrantLock();

  /** Bean names with at least one instance whose mode was read and accepted. */
  private final Set<String> verified = new HashSet<>();

  /** Bean names whose only instances were unreadable and that were decided (listed, so started). */
  private final Set<String> decidedUnreadable = new HashSet<>();

  private ListableBeanFactory beanFactory;

  /**
   * Refuses {@code agentguard.audit.hmac-secret} together with {@code
   * agentguard.audit.unkeyed=true} (B-KS-3). Shared with the starter's own {@code AuditChain} bean
   * so the message is the same.
   */
  static void refuseContradiction(AgentGuardProperties.Audit audit) {
    if (secretSet(audit) && audit.isUnkeyed()) {
      throw new AgentGuardConfigurationException(
          "agentguard.audit.unkeyed=true contradicts agentguard.audit.hmac-secret (set): a trail is"
              + " keyed from row 1 or unkeyed forever, so both cannot be asked for at once. Remove"
              + " agentguard.audit.hmac-secret to run unkeyed, or remove agentguard.audit.unkeyed to"
              + " run keyed.");
    }
  }

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
    see(bean, beanName, false);
    return bean;
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) {
    see(bean, beanName, true);
    return bean;
  }

  /**
   * Decides at once, whatever the phase, so nothing can write with the sink before (B-KS-1). A
   * readable instance decides the bean name; an unreadable one is decided in the after-hook only,
   * once the before-hook had its chance to read the raw instance behind a wrapper.
   */
  private void see(Object bean, String beanName, boolean afterInit) {
    if (!(bean instanceof AuditSink)) {
      return;
    }
    AgentGuardProperties.Audit audit = audit();
    refuseContradiction(audit);
    Mode mode = mode(bean);
    if (mode != Mode.UNKNOWN) {
      decideKnown(beanName, bean, mode, audit);
      markVerified(beanName);
      return;
    }
    if (!afterInit || isVerified(beanName)) {
      return;
    }
    decideUnreadable(beanName, bean, audit);
  }

  private void markVerified(String beanName) {
    lock.lock();
    try {
      verified.add(beanName);
    } finally {
      lock.unlock();
    }
  }

  private boolean isVerified(String beanName) {
    lock.lock();
    try {
      return verified.contains(beanName);
    } finally {
      lock.unlock();
    }
  }

  @Override
  public void afterSingletonsInstantiated() {
    // creates lazy sinks now, so they are decided at startup and not at their first use
    Map<String, AuditSink> sinks =
        new TreeMap<>(beanFactory.getBeansOfType(AuditSink.class, false, true));
    AgentGuardProperties.Audit audit = audit();
    refuseContradiction(audit);
    // a sink created before this post-processor was registered never reached the hooks
    sinks.forEach(
        (name, bean) -> {
          boolean seen;
          lock.lock();
          try {
            seen = verified.contains(name) || decidedUnreadable.contains(name);
          } finally {
            lock.unlock();
          }
          if (seen) {
            return;
          }
          Mode mode = mode(bean);
          if (mode == Mode.UNKNOWN) {
            decideUnreadable(name, bean, audit);
          } else {
            decideKnown(name, bean, mode, audit);
            markVerified(name);
          }
        });
    if (audit.isUnkeyed()) {
      log.warn(
          "agentguard.audit.unkeyed=true: the audit trail is unkeyed; a database writer can rewrite"
              + " it undetected. Local development only; set agentguard.audit.hmac-secret in"
              + " production.");
    }
    Set<String> started;
    lock.lock();
    try {
      started = new HashSet<>(decidedUnreadable);
    } finally {
      lock.unlock();
    }
    for (String listed : audit.getUnverifiedSinks()) {
      if (!started.contains(listed)) {
        log.warn(
            "agentguard.audit.unverified-sinks lists '{}', which is no audit sink bean the starter"
                + " cannot read; remove the entry",
            listed);
      }
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
          // null for a scoped proxy: its target is not a singleton, so it stays unreadable
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

  private static String describe(String beanName, Object bean) {
    return "the audit sink bean '" + beanName + "' (" + bean.getClass().getName() + ")";
  }

  private static void decideKnown(
      String beanName, Object bean, Mode mode, AgentGuardProperties.Audit audit) {
    if (mode != Mode.UNKEYED) {
      // keyed is acceptable; a key other than the secret fails verification loudly
      return;
    }
    if (secretSet(audit)) {
      throw new AgentGuardException(
          ErrorCodes.AUDIT_SINK_UNKEYED,
          "agentguard.audit.hmac-secret is set but "
              + describe(beanName, bean)
              + " is unkeyed: its rows would carry key_id=none and the verifier would report"
              + " INTACT_UNKEYED. Build it with the AuditChain bean, for example new"
              + " JdbcAuditSink(dataSource, auditChain), or remove the bean and let the"
              + " starter build it.");
    }
    if (!audit.isUnkeyed()) {
      throw new AgentGuardException(
          ErrorCodes.AUDIT_SINK_UNKEYED,
          describe(beanName, bean)
              + " is unkeyed but agentguard.audit.unkeyed=true is not set. Set"
              + " agentguard.audit.hmac-secret and build the sink with the AuditChain bean,"
              + " or, for local development only, set agentguard.audit.unkeyed=true.");
    }
  }

  private void decideUnreadable(String beanName, Object bean, AgentGuardProperties.Audit audit) {
    if (!audit.getUnverifiedSinks().contains(beanName)) {
      throw new AgentGuardException(
          ErrorCodes.AUDIT_SINK_UNKEYED,
          describe(beanName, bean)
              + " is not a sink the starter can read, so it cannot verify that it is keyed. Build"
              + " it as a JdbcAuditSink or InMemoryAuditSink with the AuditChain bean, or list"
              + " the bean name in agentguard.audit.unverified-sinks to start it anyway (it then"
              + " WARNs at every startup).");
    }
    lock.lock();
    try {
      decidedUnreadable.add(beanName);
    } finally {
      lock.unlock();
    }
    log.warn(
        "agentguard.audit.unverified-sinks: {} is listed, so it starts, but the starter cannot"
            + " verify that it is keyed. Make sure it signs rows with the AuditChain bean; the"
            + " verifier reports INTACT_UNKEYED on an unkeyed trail.",
        describe(beanName, bean));
  }
}

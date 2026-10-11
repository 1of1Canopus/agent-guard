package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.domain.AuditAnchor;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * Hands every {@code JdbcAuditSink} bean of the context to {@link AgentGuardSchemaGate#checkSink}
 * (B-RC12-1).
 *
 * <ul>
 *   <li>As a {@link BeanPostProcessor} it sees each sink instance as it is created, whatever its
 *       declared bean type. During startup it only records the sink: the starter's own sink is
 *       built from the gate, so a lookup here would be a circular reference.
 *   <li>As a {@link SmartInitializingSingleton}, once the singletons exist, it first creates every
 *       bean declared as {@code AuditSink}, {@code AuditReader} or {@code AuditAnchor} (so a lazy
 *       sink, under {@code spring.main.lazy-initialization=true} or {@code @Lazy}, is checked at
 *       startup and not at its first use), then checks every recorded sink. A failure refuses the
 *       context.
 *   <li>A sink created after startup (prototype scope, a lazy bean of another declared type) is
 *       checked as it is created, and its creation fails if the check fails.
 * </ul>
 *
 * <p>Not covered: a {@code JdbcAuditSink} built inside another bean and never exposed as a bean.
 * Such a sink must call {@code JdbcSupport.verifyGuards} itself.
 */
final class JdbcAuditSinkDataSourceCheck
    implements BeanPostProcessor, SmartInitializingSingleton, BeanFactoryAware {

  private final ObjectProvider<AgentGuardSchemaGate> schemaGate;
  private final ReentrantLock lock = new ReentrantLock();
  private final Map<String, JdbcAuditSink> recorded = new LinkedHashMap<>();
  private boolean started;
  private ListableBeanFactory beanFactory;

  JdbcAuditSinkDataSourceCheck(ObjectProvider<AgentGuardSchemaGate> schemaGate) {
    this.schemaGate = schemaGate;
  }

  @Override
  public void setBeanFactory(BeanFactory beanFactory) {
    if (!(beanFactory instanceof ListableBeanFactory listable)) {
      throw new AgentGuardConfigurationException(
          "agentguard: the JdbcAuditSink check needs a ListableBeanFactory, got "
              + beanFactory.getClass().getName());
    }
    this.beanFactory = listable;
  }

  @Override
  public Object postProcessAfterInitialization(Object bean, String beanName) {
    if (bean instanceof JdbcAuditSink sink) {
      lock.lock();
      try {
        if (!started) {
          recorded.put(beanName, sink);
          return bean;
        }
      } finally {
        lock.unlock();
      }
      schemaGate.getObject().checkSink(beanName, sink);
    }
    return bean;
  }

  @Override
  public void afterSingletonsInstantiated() {
    for (Class<?> port : List.of(AuditSink.class, AuditReader.class, AuditAnchor.class)) {
      beanFactory.getBeansOfType(port, false, true);
    }
    Map<String, JdbcAuditSink> sinks;
    lock.lock();
    try {
      started = true;
      sinks = Map.copyOf(recorded);
      recorded.clear();
    } finally {
      lock.unlock();
    }
    AgentGuardSchemaGate gate = schemaGate.getObject();
    new TreeMap<>(sinks).forEach(gate::checkSink);
  }
}

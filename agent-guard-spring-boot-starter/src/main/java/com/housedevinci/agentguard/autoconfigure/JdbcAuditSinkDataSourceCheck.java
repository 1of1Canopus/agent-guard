package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.jdbc.JdbcAuditSink;
import com.housedevinci.agentguard.adapter.jdbc.JdbcBudgetStore;
import com.housedevinci.agentguard.adapter.jdbc.JdbcDecisionStore;
import com.housedevinci.agentguard.domain.AuditAnchor;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.BudgetStore;
import com.housedevinci.agentguard.domain.DecisionStore;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import javax.sql.DataSource;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;

/**
 * Hands every {@code JdbcAuditSink}, {@code JdbcDecisionStore} and {@code JdbcBudgetStore} bean of
 * the context to {@link AgentGuardSchemaGate#checkStore} (B-RC12-1, B-RC12-4, B-RC12-5).
 *
 * <ul>
 *   <li>It is {@link PriorityOrdered} at the highest precedence, so it is registered before any
 *       ordered or plain application post-processor, and sees a store created as the dependency of
 *       one of those.
 *   <li>As a {@link BeanPostProcessor} it sees each store instance as it is created, whatever its
 *       declared bean type: before initialization (the raw instance, before any post-processor
 *       wraps it) and after (a {@code FactoryBean} product only gets this call). During startup it
 *       only records the store: the starter's own stores are built from the gate, so a lookup here
 *       would be a circular reference.
 *   <li>As a {@link SmartInitializingSingleton}, once the singletons exist, it first creates every
 *       bean declared by one of the store ports (so a lazy store, under {@code
 *       spring.main.lazy-initialization=true} or {@code @Lazy}, is checked at startup and not at
 *       its first use). It then checks every recorded store, plus every store singleton the bean
 *       factory holds (one created before this check was registered). A failure refuses the
 *       context.
 *   <li>A store created after startup (prototype scope, a lazy bean of another declared type) is
 *       checked as it is created, and its creation fails if the check fails.
 * </ul>
 *
 * <p>Not covered: a store built inside another bean and never exposed as a bean (it must call
 * {@code JdbcSupport.verifyGuards} itself), and a store created before this check is registered
 * that a post-processor registered even earlier also wraps.
 */
final class JdbcAuditSinkDataSourceCheck
    implements BeanPostProcessor, PriorityOrdered, SmartInitializingSingleton, BeanFactoryAware {

  private static final List<Class<?>> PORTS =
      List.of(
          AuditSink.class,
          AuditReader.class,
          AuditAnchor.class,
          DecisionStore.class,
          BudgetStore.class);

  private static final List<Class<?>> STORES =
      List.of(JdbcAuditSink.class, JdbcDecisionStore.class, JdbcBudgetStore.class);

  /** One JDBC store bean: its class name, bean name and the {@code DataSource} it uses. */
  private record Store(String kind, String beanName, DataSource dataSource) {}

  private final ObjectProvider<AgentGuardSchemaGate> schemaGate;
  private final ReentrantLock lock = new ReentrantLock();
  private final Set<Store> recorded = new LinkedHashSet<>();
  private boolean started;
  private ListableBeanFactory beanFactory;

  JdbcAuditSinkDataSourceCheck(ObjectProvider<AgentGuardSchemaGate> schemaGate) {
    this.schemaGate = schemaGate;
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

  @Override
  public void setBeanFactory(BeanFactory beanFactory) {
    if (!(beanFactory instanceof ListableBeanFactory listable)) {
      throw new AgentGuardConfigurationException(
          "agentguard: the JDBC store check needs a ListableBeanFactory, got "
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
    Optional<Store> store = store(bean, beanName);
    if (store.isEmpty()) {
      return;
    }
    lock.lock();
    try {
      if (!started) {
        recorded.add(store.get());
        return;
      }
    } finally {
      lock.unlock();
    }
    check(store.get());
  }

  private static Optional<Store> store(Object bean, String beanName) {
    return switch (bean) {
      case JdbcAuditSink s -> Optional.of(new Store("JdbcAuditSink", beanName, s.dataSource()));
      case JdbcDecisionStore s ->
          Optional.of(new Store("JdbcDecisionStore", beanName, s.dataSource()));
      case JdbcBudgetStore s -> Optional.of(new Store("JdbcBudgetStore", beanName, s.dataSource()));
      default -> Optional.empty();
    };
  }

  private void check(Store store) {
    schemaGate.getObject().checkStore(store.kind(), store.beanName(), store.dataSource());
  }

  @Override
  public void afterSingletonsInstantiated() {
    for (Class<?> port : PORTS) {
      beanFactory.getBeansOfType(port, false, true);
    }
    Set<Store> stores;
    lock.lock();
    try {
      started = true;
      stores = new LinkedHashSet<>(recorded);
      recorded.clear();
    } finally {
      lock.unlock();
    }
    // singletons only: a prototype is checked when it is created, not instantiated here
    for (Class<?> type : STORES) {
      beanFactory
          .getBeansOfType(type, false, false)
          .forEach((name, bean) -> store(bean, name).ifPresent(stores::add));
    }
    List<Store> ordered = new ArrayList<>(stores);
    ordered.sort(Comparator.comparing(Store::beanName).thenComparing(Store::kind));
    ordered.forEach(this::check);
  }
}

package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.jdbc.JdbcSupport;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;

/**
 * The one place the starter hands a {@link DataSource} to the JDBC stores, and the startup check of
 * the audit trail's guards. Always registered and never lazy, so the check runs whether the stores
 * are the starter's beans or the application's own (CP34-1). Whether the starter's JDBC stores are
 * in use is decided from the properties: {@code agentguard.store=JDBC}, or {@code
 * agentguard.budgets.store=JDBC}. If not, {@link #dataSource()} refuses, and the check runs only if
 * a JDBC store bean exists (below). If so, the gate refuses to start the context at its
 * construction unless the audit trail's guards hold:
 *
 * <ul>
 *   <li>{@code agentguard.jdbc.initialize-schema=true}: the bundled script and the guard check run
 *       in one transaction (once per {@code DataSource} per JVM for the script; the check runs
 *       again in every later context);
 *   <li>{@code agentguard.jdbc.initialize-schema=false}: the guard check alone, read-only.
 * </ul>
 *
 * <p>Which {@code DataSource} is checked: the one named by {@code
 * agentguard.schema.gate.datasource}, else the primary one. A name that is no {@code DataSource}
 * bean refuses with {@code AG-SCHEMA-007}.
 *
 * <p>Every {@code JdbcAuditSink}, {@code JdbcDecisionStore} and {@code JdbcBudgetStore} bean,
 * whatever the store properties say, is handed to {@link #checkStore} ({@link
 * JdbcAuditSinkDataSourceCheck}). Its {@code DataSource} must be the checked one by identity, or
 * startup is refused with {@code AG-SCHEMA-007}. When the properties configure no JDBC store, the
 * first such bean triggers the guard check (read-only, the schema step does not run) on the checked
 * {@code DataSource}.
 *
 * <p>Ordered after Flyway, Liquibase and {@code spring.sql.init} by {@code
 * DependsOnDatabaseInitialization} on its bean method, so a migration that creates the schema in
 * the same boot runs first.
 */
public final class AgentGuardSchemaGate {

  private static final Logger log = LoggerFactory.getLogger(AgentGuardSchemaGate.class);

  /** DataSources whose schema script already ran in this JVM (L10: once, not per bean). */
  private static final Set<Integer> SCRIPT_DONE = ConcurrentHashMap.newKeySet();

  private final Optional<DataSource> dataSource;
  private final Optional<String> namedDataSource;
  private final ObjectProvider<DataSource> dataSources;
  private final ListableBeanFactory beans;

  /** Guards {@link #checked}; a lock rather than {@code synchronized} (virtual threads, JDK 21). */
  private final ReentrantLock lock = new ReentrantLock();

  /** The {@code DataSource} whose guards passed the check in this context, once one did. */
  private DataSource checked;

  AgentGuardSchemaGate(
      AgentGuardProperties props,
      ObjectProvider<DataSource> dataSources,
      ListableBeanFactory beans) {
    this.dataSources = dataSources;
    this.beans = beans;
    this.namedDataSource = Optional.ofNullable(props.getSchema().getGate().getDatasource());
    // an unknown name refuses at startup even when no JDBC store is configured: a typo in the
    // property that picks the checked DataSource must never pass silently
    Optional<DataSource> named = namedDataSource.map(this::namedBean);
    if (!jdbcInUse(props)) {
      this.dataSource = Optional.empty();
      return;
    }
    DataSource ds = named.orElseGet(dataSources::getIfAvailable);
    if (ds == null) {
      throw new AgentGuardConfigurationException(
          "agentguard.store=JDBC requires a DataSource bean when agentguard.enabled=true, but no"
              + " DataSource found (add spring-boot-starter-jdbc + spring.datasource.*). For a local"
              + " trial set agentguard.store=memory - not for production.");
    }
    verify(props, ds);
    this.checked = ds;
    this.dataSource = Optional.of(ds);
  }

  private DataSource namedBean(String name) {
    try {
      return beans.getBean(name, DataSource.class);
    } catch (BeansException e) {
      throw new AgentGuardException(
          ErrorCodes.SCHEMA_DATASOURCE_MISMATCH,
          "agentguard: agentguard.schema.gate.datasource="
              + name
              + " names no DataSource bean, so the audit trail guards cannot be checked on it. Set"
              + " it to the bean name of the DataSource the audit trail is written through.");
    }
  }

  /**
   * Refuses unless the JDBC store bean {@code beanName} (of class {@code kind}) uses the {@code
   * DataSource} whose guards passed the check, compared by identity. When no check ran yet (no JDBC
   * store in the properties), runs it first on the named or primary {@code DataSource}, read-only.
   *
   * @throws AgentGuardException {@code AG-SCHEMA-007} on a different {@code DataSource} or when
   *     there is none to check; {@code AG-SCHEMA-003} or {@code AG-SCHEMA-005} from the check
   */
  void checkStore(String kind, String beanName, DataSource storeDataSource) {
    DataSource verified = checkedForStores(kind, beanName);
    if (storeDataSource != verified) {
      throw new AgentGuardException(
          ErrorCodes.SCHEMA_DATASOURCE_MISMATCH,
          "agentguard: the "
              + kind
              + " bean '"
              + beanName
              + "' uses "
              + describe(storeDataSource)
              + ", but the audit trail guards were checked on "
              + describe(verified)
              + ". Set agentguard.schema.gate.datasource to the bean name of the DataSource the"
              + " agent-guard tables are reached through. Compared by identity: a proxy or a pool"
              + " around the checked DataSource is a different one.");
    }
  }

  private DataSource checkedForStores(String kind, String beanName) {
    lock.lock();
    try {
      if (checked == null) {
        DataSource ds = namedDataSource.map(this::namedBean).orElseGet(dataSources::getIfAvailable);
        if (ds == null) {
          throw new AgentGuardException(
              ErrorCodes.SCHEMA_DATASOURCE_MISMATCH,
              "agentguard: the "
                  + kind
                  + " bean '"
                  + beanName
                  + "' exists but no DataSource bean is there to check the agent-guard table"
                  + " guards on. Expose that DataSource as a bean and name it in"
                  + " agentguard.schema.gate.datasource.");
        }
        JdbcSupport.verifyGuards(ds);
        log.info(
            "agentguard: audit trail guards verified at startup for the {} bean '{}' (no JDBC"
                + " store in the properties; read-only check, no schema step)",
            kind,
            beanName);
        checked = ds;
      }
      return checked;
    } finally {
      lock.unlock();
    }
  }

  /** The bean name(s) of {@code ds} found by identity, or a note that it is not a bean. */
  private String describe(DataSource ds) {
    String names =
        beans.getBeansOfType(DataSource.class, true, false).entrySet().stream()
            .filter(e -> e.getValue() == ds)
            .map(e -> "'" + e.getKey() + "'")
            .collect(Collectors.joining(", "));
    return names.isEmpty()
        ? "a DataSource that is not a bean (" + ds.getClass().getName() + ")"
        : "the DataSource bean " + names;
  }

  /** JDBC is in use when the decision/audit store or the budget store is configured as JDBC. */
  static boolean jdbcInUse(AgentGuardProperties props) {
    return props.getStore() == AgentGuardProperties.StoreType.JDBC
        || props.getBudgets().getStore() == AgentGuardProperties.BudgetStoreType.JDBC;
  }

  private static void verify(AgentGuardProperties props, DataSource dataSource) {
    Integer id = System.identityHashCode(dataSource);
    if (props.getJdbc().isInitializeSchema() && !SCRIPT_DONE.contains(id)) {
      JdbcSupport.initializeSchemaAndVerifyGuards(dataSource);
      SCRIPT_DONE.add(id);
      log.info("agentguard: schema step ran (agentguard.jdbc.initialize-schema=true)");
      warnIfOwner(dataSource);
    } else {
      JdbcSupport.verifyGuards(dataSource);
    }
    log.info(
        "agentguard: audit trail guards verified at startup (5 triggers ENABLE ALWAYS with the"
            + " bundled bodies; no extra trigger, rule, row level security, policy or inheritance"
            + " on the four tables). Checked at startup only.");
  }

  private static void warnIfOwner(DataSource ds) {
    try {
      if (JdbcSupport.runtimeRoleOwnsAuditTable(ds)) {
        log.warn(
            "agentguard: the runtime database role owns agentguard_audit or is a member of the"
                + " role that owns it, and can disable its append-only triggers; use a separate owner role for the schema and a runtime role"
                + " with INSERT/SELECT only (docs, \"Database roles\")");
      }
    } catch (RuntimeException e) {
      log.debug("agentguard: could not determine the audit table owner: {}", e.toString());
    }
  }

  /**
   * The verified {@code DataSource}.
   *
   * @throws AgentGuardConfigurationException when the properties configure no JDBC store, so no
   *     check ran and no {@code DataSource} was verified
   */
  public DataSource dataSource() {
    return dataSource.orElseThrow(
        () ->
            new AgentGuardConfigurationException(
                "agentguard: a JDBC store was requested but neither agentguard.store nor"
                    + " agentguard.budgets.store is JDBC, so the audit trail guards were not"
                    + " checked; set the store property to JDBC"));
  }

  /** The verified {@code DataSource}, empty when no JDBC store is configured. */
  Optional<DataSource> verifiedDataSource() {
    return dataSource;
  }
}

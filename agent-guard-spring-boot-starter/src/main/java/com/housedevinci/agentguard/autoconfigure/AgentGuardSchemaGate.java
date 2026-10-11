package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.jdbc.JdbcSupport;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;

/**
 * The one place the starter hands a {@link DataSource} to the JDBC stores, and the startup check of
 * the audit trail's guards. Always registered and never lazy, so the check runs whether the stores
 * are the starter's beans or the application's own (CP34-1). Whether JDBC is in use is decided from
 * the properties alone: {@code agentguard.store=JDBC}, or {@code agentguard.budgets.store=JDBC}. If
 * it is not, the gate holds no {@code DataSource}, needs none, and {@link #dataSource()} refuses.
 * If it is, the gate refuses to start the context unless the audit trail's guards hold:
 *
 * <ul>
 *   <li>{@code agentguard.jdbc.initialize-schema=true}: the bundled script and the guard check run
 *       in one transaction (once per {@code DataSource} per JVM for the script; the check runs
 *       again in every later context);
 *   <li>{@code agentguard.jdbc.initialize-schema=false}: the guard check alone, read-only.
 * </ul>
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

  AgentGuardSchemaGate(AgentGuardProperties props, ObjectProvider<DataSource> dataSources) {
    if (!jdbcInUse(props)) {
      this.dataSource = Optional.empty();
      return;
    }
    DataSource ds = dataSources.getIfAvailable();
    if (ds == null) {
      throw new AgentGuardConfigurationException(
          "agentguard.store=JDBC requires a DataSource bean when agentguard.enabled=true, but no"
              + " DataSource found (add spring-boot-starter-jdbc + spring.datasource.*). For a local"
              + " trial set agentguard.store=memory - not for production.");
    }
    verify(props, ds);
    this.dataSource = Optional.of(ds);
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
            "agentguard: the runtime database role owns agentguard_audit and can disable its"
                + " append-only triggers; use a separate owner role for the schema and a runtime role"
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

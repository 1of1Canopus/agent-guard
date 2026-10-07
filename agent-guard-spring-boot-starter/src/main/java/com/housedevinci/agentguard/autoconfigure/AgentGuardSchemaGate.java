package com.housedevinci.agentguard.autoconfigure;

import com.housedevinci.agentguard.adapter.jdbc.JdbcSupport;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The one place the starter hands a {@link DataSource} to the JDBC stores. Built, once per context,
 * the first time a JDBC-backed decision store, audit sink or budget store is created, and never in
 * a context that uses none. On every boot path it refuses to hand the {@code DataSource} out unless
 * the audit trail's guards hold:
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

  private final DataSource dataSource;

  AgentGuardSchemaGate(AgentGuardProperties props, DataSource dataSource) {
    this.dataSource = dataSource;
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

  /** The verified {@code DataSource}. */
  public DataSource dataSource() {
    return dataSource;
  }
}

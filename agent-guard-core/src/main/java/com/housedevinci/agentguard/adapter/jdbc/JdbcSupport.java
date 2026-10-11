package com.housedevinci.agentguard.adapter.jdbc;

import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import javax.sql.DataSource;

/** Plain-JDBC helpers shared by the adapters. No Spring. */
public final class JdbcSupport {

  private JdbcSupport() {}

  @FunctionalInterface
  interface SqlWork<T> {
    T run(Connection c) throws SQLException;
  }

  static <T> T inTransaction(DataSource ds, SqlWork<T> work) {
    try (Connection c = ds.getConnection()) {
      boolean previous = c.getAutoCommit();
      c.setAutoCommit(false);
      try {
        T result = work.run(c);
        c.commit();
        return result;
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      } finally {
        c.setAutoCommit(previous);
      }
    } catch (SQLException e) {
      throw new JdbcAccessException(e);
    }
  }

  static <T> T withConnection(DataSource ds, SqlWork<T> work) {
    try (Connection c = ds.getConnection()) {
      return work.run(c);
    } catch (SQLException e) {
      throw new JdbcAccessException(e);
    }
  }

  static OffsetDateTime ts(Instant i) {
    return i == null ? null : i.atOffset(ZoneOffset.UTC);
  }

  static Instant instant(OffsetDateTime t) {
    return t == null ? null : t.toInstant();
  }

  /**
   * Runs the bundled PostgreSQL schema; idempotent. Meant for the role that owns the tables (a
   * migration step, a one-off job), not for an application's runtime role. Applying it repairs a
   * guard trigger that is missing, disabled or set to replica, and sets all five to {@code ENABLE
   * ALWAYS}; it changes no row of the trail or the anchor.
   */
  public static void initializeSchema(DataSource ds) {
    String sql = bundledScript();
    inTransaction(
        ds,
        c -> {
          try (Statement st = c.createStatement()) {
            st.execute(sql);
          }
          return null;
        });
  }

  /**
   * Refuses unless the audit trail's guards hold in the connection's current schema: the five
   * bundled triggers exactly, each {@code ENABLE ALWAYS} with no {@code WHEN} clause and no column
   * list, pointing at the bundled guard functions with the bundled bodies, and no rule, row level
   * security, policy or inheritance edge on the four tables. Catalogue reads only, in one read-only
   * REPEATABLE READ transaction that is rolled back. Call it at startup before handing a {@code
   * DataSource} to {@link JdbcAuditSink}, {@link JdbcDecisionStore} or {@link JdbcBudgetStore}; the
   * Spring Boot starter does.
   *
   * <p>This is a check at startup, not a lock: a role that owns the tables can still disable a
   * trigger afterwards. Run the application as a role that does not own them.
   *
   * @throws AgentGuardException {@link ErrorCodes#SCHEMA_UNGUARDED} listing every finding, or
   *     {@link ErrorCodes#SCHEMA_UNVERIFIABLE} when the check cannot complete
   */
  public static void verifyGuards(DataSource ds) {
    GuardCensus census = GuardCensus.fromBundledScript(bundledScript());
    try (Connection c = ds.getConnection()) {
      boolean autoCommit = c.getAutoCommit();
      boolean readOnly = c.isReadOnly();
      int isolation = c.getTransactionIsolation();
      if (!autoCommit) {
        c.rollback();
      }
      // both flags before setAutoCommit(false): PostgreSQL refuses either inside a transaction
      c.setReadOnly(true);
      c.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
      c.setAutoCommit(false);
      try {
        census.verify(c);
      } finally {
        c.rollback();
        c.setAutoCommit(autoCommit);
        c.setTransactionIsolation(isolation);
        c.setReadOnly(readOnly);
      }
    } catch (SQLException e) {
      throw GuardCensus.unverifiable(null, e);
    }
  }

  /**
   * The creation path ({@code agentguard.jdbc.initialize-schema=true}): runs the bundled script and
   * then {@link #verifyGuards}' census in the same transaction, under the script's advisory lock,
   * and commits only when the census is clean. When the script itself fails (most commonly: the
   * role does not own the schema), the census runs on its own and decides the refusal: {@link
   * ErrorCodes#SCHEMA_UNGUARDED} when the guards do not hold, {@link
   * ErrorCodes#SCHEMA_CREATION_FAILED} when they do. The driver's message is never surfaced, only
   * its SQLState.
   */
  public static void initializeSchemaAndVerifyGuards(DataSource ds) {
    String sql = bundledScript();
    GuardCensus census = GuardCensus.fromBundledScript(sql);
    SQLException scriptFailure = null;
    try (Connection c = ds.getConnection()) {
      boolean autoCommit = c.getAutoCommit();
      c.setAutoCommit(false);
      try {
        try (Statement st = c.createStatement()) {
          st.execute(sql);
        } catch (SQLException e) {
          scriptFailure = e;
        }
        if (scriptFailure == null) {
          census.verify(c);
          c.commit();
        }
      } finally {
        if (scriptFailure != null || !c.getAutoCommit()) {
          c.rollback();
        }
        c.setAutoCommit(autoCommit);
      }
    } catch (SQLException e) {
      throw GuardCensus.unverifiable(null, e);
    }
    if (scriptFailure != null) {
      creationFailed(ds, scriptFailure);
    }
  }

  private static void creationFailed(DataSource ds, SQLException scriptFailure) {
    String state = scriptFailure.getSQLState();
    String step =
        " The schema step (agentguard.jdbc.initialize-schema=true) failed as this role with SQLState "
            + state
            + " and repaired nothing; it must run as the role that owns the tables.";
    try {
      verifyGuards(ds);
    } catch (AgentGuardException refusal) {
      throw new AgentGuardException(refusal.code(), refusal.getMessage() + step);
    }
    throw new AgentGuardException(
        ErrorCodes.SCHEMA_CREATION_FAILED,
        "agentguard: agentguard.jdbc.initialize-schema=true but the bundled schema-postgresql.sql"
            + " failed with SQLState "
            + state
            + ". The commonest cause is that the application's role does not own the schema;"
            + " the audit trail guards are in place, so set agentguard.jdbc.initialize-schema=false"
            + " and apply the script as the owning role when it changes (docs, \"Database roles\")."
            + ("P0001".equals(state)
                ? " SQLState P0001 is also raised by the script's own check that refuses a database"
                    + " predating keyed-from-birth; see \"Starting a new trail\" in docs/index.md."
                : ""));
  }

  private static String bundledScript() {
    try (InputStream in = JdbcSupport.class.getResourceAsStream(GuardCensus.SCRIPT)) {
      if (in == null) {
        throw new IllegalStateException("schema-postgresql.sql missing from classpath");
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("cannot read schema", e);
    }
  }

  /** True when the current database role owns the audit table (and could disable its triggers). */
  public static boolean runtimeRoleOwnsAuditTable(DataSource ds) {
    return withConnection(
        ds,
        c -> {
          try (Statement st = c.createStatement();
              var rs =
                  st.executeQuery(
                      "SELECT tableowner = current_user FROM pg_tables WHERE tablename = 'agentguard_audit'")) {
            return rs.next() && rs.getBoolean(1);
          }
        });
  }

  /** Unchecked wrapper so the domain never sees {@link SQLException}. */
  public static final class JdbcAccessException extends RuntimeException {
    JdbcAccessException(SQLException cause) {
      super("Agent Guard JDBC failure: " + cause.getMessage(), cause);
    }
  }
}

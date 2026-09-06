package com.housedevinci.agentguard.adapter.jdbc;

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

  /** Runs the bundled PostgreSQL schema; idempotent. */
  public static void initializeSchema(DataSource ds) {
    String sql;
    try (InputStream in =
        JdbcSupport.class.getResourceAsStream(
            "/com/housedevinci/agentguard/schema-postgresql.sql")) {
      if (in == null) {
        throw new IllegalStateException("schema-postgresql.sql missing from classpath");
      }
      sql = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("cannot read schema", e);
    }
    inTransaction(
        ds,
        c -> {
          try (Statement st = c.createStatement()) {
            st.execute(sql);
          }
          return null;
        });
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

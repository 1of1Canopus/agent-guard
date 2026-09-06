package com.housedevinci.agentguard.adapter.jdbc;

import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.ts;

import com.housedevinci.agentguard.domain.BudgetStore;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import javax.sql.DataSource;

/** PostgreSQL counters: one atomic upsert per increment, expired rows restart from zero. */
public final class JdbcBudgetStore implements BudgetStore {

  private final DataSource dataSource;
  private final Clock clock;

  public JdbcBudgetStore(DataSource dataSource, Clock clock) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public long incrementAndGet(String key, long amount, Duration ttl) {
    var now = clock.instant();
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "INSERT INTO agentguard_budget (key, used, expires_at) VALUES (?, ?, ?) "
                      + "ON CONFLICT (key) DO UPDATE SET "
                      + "used = CASE WHEN agentguard_budget.expires_at <= ? THEN EXCLUDED.used "
                      + "ELSE agentguard_budget.used + EXCLUDED.used END, "
                      + "expires_at = CASE WHEN agentguard_budget.expires_at <= ? THEN EXCLUDED.expires_at "
                      + "ELSE agentguard_budget.expires_at END RETURNING used")) {
            ps.setString(1, key);
            ps.setLong(2, amount);
            ps.setObject(3, ts(now.plus(ttl)));
            ps.setObject(4, ts(now));
            ps.setObject(5, ts(now));
            try (ResultSet rs = ps.executeQuery()) {
              rs.next();
              return rs.getLong(1);
            }
          }
        });
  }

  @Override
  public long current(String key) {
    var now = clock.instant();
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "SELECT used FROM agentguard_budget WHERE key = ? AND expires_at > ?")) {
            ps.setString(1, key);
            ps.setObject(2, ts(now));
            try (ResultSet rs = ps.executeQuery()) {
              return rs.next() ? rs.getLong(1) : 0L;
            }
          }
        });
  }
}

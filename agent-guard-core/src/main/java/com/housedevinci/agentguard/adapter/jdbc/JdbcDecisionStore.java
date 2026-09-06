package com.housedevinci.agentguard.adapter.jdbc;

import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.instant;
import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.ts;

import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionState;
import com.housedevinci.agentguard.domain.DecisionStore;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolRef;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.sql.DataSource;

/** PostgreSQL decision store. Transitions and execute-once are single conditional UPDATEs. */
public final class JdbcDecisionStore implements DecisionStore {

  private static final String COLUMNS =
      "id, principal_id, principal_roles, principal_scopes, tenant_id, tool, side_effect, "
          + "arguments_json, args_hash, args_preview, conversation_id, correlation_id, created_at, "
          + "expires_at, state, decided_by, decided_at, executed, result_json";

  private final DataSource dataSource;

  public JdbcDecisionStore(DataSource dataSource) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
  }

  @Override
  public void save(PendingDecision d) {
    JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "INSERT INTO agentguard_decision ("
                      + COLUMNS
                      + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                      + "ON CONFLICT (id) DO UPDATE SET arguments_json = EXCLUDED.arguments_json, "
                      + "args_hash = EXCLUDED.args_hash, args_preview = EXCLUDED.args_preview, "
                      + "state = EXCLUDED.state, decided_by = EXCLUDED.decided_by, "
                      + "decided_at = EXCLUDED.decided_at, executed = EXCLUDED.executed, "
                      + "result_json = EXCLUDED.result_json")) {
            int i = 1;
            ps.setObject(i++, d.id().value());
            ps.setString(i++, d.principal().id());
            ps.setString(i++, join(d.principal().roles()));
            ps.setString(i++, join(d.principal().scopes()));
            ps.setString(i++, d.principal().tenantId().orElse(null));
            ps.setString(i++, d.tool().name());
            ps.setString(i++, d.tool().sideEffect().name());
            ps.setString(i++, d.argumentsJson());
            ps.setString(i++, d.argsHash());
            ps.setString(i++, d.argsPreview());
            ps.setString(i++, d.conversationId());
            ps.setString(i++, d.correlationId());
            ps.setObject(i++, ts(d.createdAt()));
            ps.setObject(i++, ts(d.expiresAt()));
            ps.setString(i++, d.state().name());
            ps.setString(i++, d.decidedBy());
            ps.setObject(i++, ts(d.decidedAt()));
            ps.setBoolean(i++, d.executed());
            ps.setString(i, d.resultJson());
            ps.executeUpdate();
          }
          return null;
        });
  }

  @Override
  public Optional<PendingDecision> findById(DecisionId id) {
    return query(
            "SELECT " + COLUMNS + " FROM agentguard_decision WHERE id = ?",
            ps -> ps.setObject(1, id.value()),
            1)
        .stream()
        .findFirst();
  }

  @Override
  public Optional<PendingDecision> findLatest(
      String principalId, String tenantId, String tool, String argsHash) {
    return query(
            "SELECT "
                + COLUMNS
                + " FROM agentguard_decision WHERE principal_id = ? "
                + "AND tenant_id IS NOT DISTINCT FROM ? AND tool = ? AND args_hash = ? "
                + "ORDER BY created_at DESC LIMIT 1",
            ps -> {
              ps.setString(1, principalId);
              ps.setString(2, tenantId);
              ps.setString(3, tool);
              ps.setString(4, argsHash);
            },
            1)
        .stream()
        .findFirst();
  }

  @Override
  public long countPending(String principalId) {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "SELECT count(*) FROM agentguard_decision WHERE principal_id = ? AND state = 'PENDING'")) {
            ps.setString(1, principalId);
            try (ResultSet rs = ps.executeQuery()) {
              rs.next();
              return rs.getLong(1);
            }
          }
        });
  }

  @Override
  public List<PendingDecision> findByState(DecisionState state, int limit) {
    int capped = Math.max(1, Math.min(limit, 1000));
    return query(
        "SELECT "
            + COLUMNS
            + " FROM agentguard_decision WHERE state = ? ORDER BY created_at LIMIT ?",
        ps -> {
          ps.setString(1, state.name());
          ps.setInt(2, capped);
        },
        capped);
  }

  @Override
  public boolean transition(
      DecisionId id, DecisionState expected, DecisionState target, String by, Instant at) {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "UPDATE agentguard_decision SET state = ?, decided_by = ?, decided_at = ? "
                      + "WHERE id = ? AND state = ?")) {
            ps.setString(1, target.name());
            ps.setString(2, by);
            ps.setObject(3, ts(at));
            ps.setObject(4, id.value());
            ps.setString(5, expected.name());
            return ps.executeUpdate() == 1;
          }
        });
  }

  @Override
  public boolean markExecutedOnce(DecisionId id) {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "UPDATE agentguard_decision SET executed = true WHERE id = ? AND executed = false")) {
            ps.setObject(1, id.value());
            return ps.executeUpdate() == 1;
          }
        });
  }

  @Override
  public void storeResult(DecisionId id, String resultJson) {
    JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "UPDATE agentguard_decision SET result_json = ?, executed = true WHERE id = ?")) {
            ps.setString(1, resultJson);
            ps.setObject(2, id.value());
            ps.executeUpdate();
          }
          return null;
        });
  }

  @FunctionalInterface
  private interface Binder {
    void bind(PreparedStatement ps) throws SQLException;
  }

  private List<PendingDecision> query(String sql, Binder binder, int expected) {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
              var out = new ArrayList<PendingDecision>(expected);
              while (rs.next()) {
                out.add(map(rs));
              }
              return out;
            }
          }
        });
  }

  private static PendingDecision map(ResultSet rs) throws SQLException {
    var principal =
        new Principal(
            rs.getString("principal_id"),
            split(rs.getString("principal_roles")),
            split(rs.getString("principal_scopes")),
            rs.getString("tenant_id"));
    return new PendingDecision(
        new DecisionId(rs.getObject("id", UUID.class)),
        principal,
        new ToolRef(rs.getString("tool"), SideEffect.valueOf(rs.getString("side_effect"))),
        rs.getString("arguments_json"),
        rs.getString("args_hash"),
        rs.getString("args_preview"),
        rs.getString("conversation_id"),
        rs.getString("correlation_id"),
        instant(rs.getObject("created_at", OffsetDateTime.class)),
        instant(rs.getObject("expires_at", OffsetDateTime.class)),
        DecisionState.valueOf(rs.getString("state")),
        rs.getString("decided_by"),
        instant(rs.getObject("decided_at", OffsetDateTime.class)),
        rs.getBoolean("executed"),
        rs.getString("result_json"));
  }

  private static String join(Set<String> values) {
    return values.stream().sorted().collect(Collectors.joining(","));
  }

  private static Set<String> split(String csv) {
    if (csv == null || csv.isBlank()) {
      return Set.of();
    }
    return Arrays.stream(csv.split(","))
        .map(String::strip)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toSet());
  }
}

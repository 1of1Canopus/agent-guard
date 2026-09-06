package com.housedevinci.agentguard.adapter.jdbc;

import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.instant;
import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.ts;

import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.sql.DataSource;

/**
 * PostgreSQL audit sink. Each append runs in its own transaction under a transaction-scoped
 * advisory lock so the chain is linear even under concurrent writers; the table's trigger refuses
 * UPDATE and DELETE.
 */
public final class JdbcAuditSink implements AuditSink, AuditReader {

  private static final String COLUMNS =
      "seq, ts, principal_id, tenant_id, tool, args_hash, result_hash, latency_ms, decision, "
          + "correlation_id, decision_id, prev_hash, hash";
  private static final long LOCK_KEY = 0x41474741554449L; // "AGGAUDI"

  private final DataSource dataSource;

  public JdbcAuditSink(DataSource dataSource) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
  }

  @Override
  public AuditEvent append(AuditEvent event) {
    return JdbcSupport.inTransaction(
        dataSource,
        c -> {
          try (PreparedStatement lock = c.prepareStatement("SELECT pg_advisory_xact_lock(?)")) {
            lock.setLong(1, LOCK_KEY);
            lock.execute();
          }
          String prev = AuditChain.GENESIS;
          try (PreparedStatement last =
                  c.prepareStatement(
                      "SELECT hash FROM agentguard_audit ORDER BY seq DESC LIMIT 1");
              ResultSet rs = last.executeQuery()) {
            if (rs.next()) {
              prev = rs.getString(1);
            }
          }
          var linked = AuditChain.link(event, prev);
          try (PreparedStatement ps =
              c.prepareStatement(
                  "INSERT INTO agentguard_audit (ts, principal_id, tenant_id, tool, args_hash, "
                      + "result_hash, latency_ms, decision, correlation_id, decision_id, prev_hash, hash) "
                      + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq")) {
            int i = 1;
            ps.setObject(i++, ts(linked.timestamp()));
            ps.setString(i++, linked.principalId());
            ps.setString(i++, linked.tenantId());
            ps.setString(i++, linked.tool());
            ps.setString(i++, linked.argsHash());
            ps.setString(i++, linked.resultHash());
            ps.setLong(i++, linked.latencyMillis());
            ps.setString(i++, linked.decision().name());
            ps.setString(i++, linked.correlationId());
            ps.setString(i++, linked.decisionId());
            ps.setString(i++, linked.prevHash());
            ps.setString(i, linked.hash());
            try (ResultSet rs = ps.executeQuery()) {
              rs.next();
              return linked.withSequence(rs.getLong(1));
            }
          }
        });
  }

  @Override
  public List<AuditEvent> readAfter(long afterSequence, int limit) {
    return read(
        "SELECT " + COLUMNS + " FROM agentguard_audit WHERE seq > ? ORDER BY seq ASC LIMIT ?",
        afterSequence,
        limit);
  }

  @Override
  public List<AuditEvent> latest(int limit) {
    return read(
        "SELECT " + COLUMNS + " FROM agentguard_audit WHERE seq > ? ORDER BY seq DESC LIMIT ?",
        0,
        limit);
  }

  private List<AuditEvent> read(String sql, long after, int limit) {
    int capped = Math.max(1, Math.min(limit, 1000));
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, after);
            ps.setInt(2, capped);
            try (ResultSet rs = ps.executeQuery()) {
              var out = new ArrayList<AuditEvent>();
              while (rs.next()) {
                out.add(map(rs));
              }
              return out;
            }
          }
        });
  }

  private static AuditEvent map(ResultSet rs) throws SQLException {
    return new AuditEvent(
        rs.getLong("seq"),
        instant(rs.getObject("ts", OffsetDateTime.class)),
        rs.getString("principal_id"),
        rs.getString("tenant_id"),
        rs.getString("tool"),
        rs.getString("args_hash"),
        rs.getString("result_hash"),
        rs.getLong("latency_ms"),
        AuditDecision.valueOf(rs.getString("decision")),
        rs.getString("correlation_id"),
        rs.getString("decision_id"),
        rs.getString("prev_hash"),
        rs.getString("hash"));
  }
}

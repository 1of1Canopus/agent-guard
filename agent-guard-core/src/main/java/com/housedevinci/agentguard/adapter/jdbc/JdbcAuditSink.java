package com.housedevinci.agentguard.adapter.jdbc;

import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.instant;
import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.ts;

import com.housedevinci.agentguard.domain.AuditAnchor;
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
import java.util.Optional;
import javax.sql.DataSource;

/**
 * PostgreSQL audit sink. Each append runs in its own transaction under a transaction-scoped
 * advisory lock so the chain is linear even under concurrent writers; the table's trigger refuses
 * UPDATE and DELETE.
 */
public final class JdbcAuditSink implements AuditSink, AuditReader, AuditAnchor {

  private static final String COLUMNS =
      "seq, ts, principal_id, tenant_id, tool, args_hash, result_hash, latency_ms, decision, "
          + "correlation_id, decision_id, actor_id, chain_version, prev_hash, hash";
  private static final org.slf4j.Logger log =
      org.slf4j.LoggerFactory.getLogger(JdbcAuditSink.class);
  private static final java.util.concurrent.atomic.AtomicBoolean WARNED_MISSING_ANCHOR =
      new java.util.concurrent.atomic.AtomicBoolean();
  private static final long LOCK_KEY = 0x41474741554449L; // "AGGAUDI"

  private final DataSource dataSource;
  private final AuditChain chain;

  public JdbcAuditSink(DataSource dataSource) {
    this(dataSource, AuditChain.unkeyed());
  }

  public JdbcAuditSink(DataSource dataSource, AuditChain chain) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    this.chain = Objects.requireNonNull(chain, "chain");
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
          long count = 0;
          Long keyedFromSeq = null;
          boolean anchored = false;
          try (PreparedStatement last =
                  c.prepareStatement(
                      "SELECT head_hash, row_count, keyed_from_seq FROM agentguard_audit_anchor"
                          + " WHERE id = 1");
              ResultSet rs = last.executeQuery()) {
            if (rs.next()) {
              prev = rs.getString(1);
              count = rs.getLong(2);
              keyedFromSeq = (Long) rs.getObject(3);
              anchored = true;
            }
          }
          if (!anchored) {
            // no anchor row (trail older than the anchor, or the row was removed): continue from
            // the table's actual head rather than restarting the chain at GENESIS
            try (PreparedStatement head =
                    c.prepareStatement(
                        "SELECT hash, (SELECT count(*) FROM agentguard_audit) FROM agentguard_audit"
                            + " ORDER BY seq DESC LIMIT 1");
                ResultSet rs = head.executeQuery()) {
              if (rs.next()) {
                prev = rs.getString(1);
                count = rs.getLong(2);
                if (WARNED_MISSING_ANCHOR.compareAndSet(false, true)) {
                  log.warn(
                      "agentguard_audit_anchor row missing; re-anchoring from the trail head"
                          + " (seq count {}). Run the schema step to seed it.",
                      count);
                }
              }
            }
            // re-derive when the keyed chain first appeared in the existing trail, so a lost or
            // pre-anchor row does not silently forget it (V2)
            try (PreparedStatement first =
                c.prepareStatement(
                    "SELECT min(seq) FROM agentguard_audit WHERE chain_version = ?")) {
              first.setString(1, AuditChain.KEYED_VERSION);
              try (ResultSet rs = first.executeQuery()) {
                if (rs.next()) {
                  keyedFromSeq = (Long) rs.getObject(1);
                }
              }
            }
          }
          var linked = chain.linkEvent(event, prev);
          if (keyedFromSeq == null && AuditChain.KEYED_VERSION.equals(linked.version())) {
            keyedFromSeq = count + 1;
          }
          try (PreparedStatement anchor =
              c.prepareStatement(
                  "INSERT INTO agentguard_audit_anchor (id, head_hash, row_count, updated_at,"
                      + " keyed_from_seq) VALUES (1, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET "
                      + "head_hash = EXCLUDED.head_hash, row_count = EXCLUDED.row_count, "
                      + "updated_at = EXCLUDED.updated_at, keyed_from_seq = EXCLUDED.keyed_from_seq")) {
            anchor.setString(1, linked.hash());
            anchor.setLong(2, count + 1);
            anchor.setObject(3, ts(linked.timestamp()));
            anchor.setObject(4, keyedFromSeq);
            anchor.executeUpdate();
          }
          try (PreparedStatement ps =
              c.prepareStatement(
                  "INSERT INTO agentguard_audit (ts, principal_id, tenant_id, tool, args_hash, "
                      + "result_hash, latency_ms, decision, correlation_id, decision_id, actor_id, "
                      + "chain_version, prev_hash, hash) "
                      + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq")) {
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
            ps.setString(i++, linked.actorId());
            ps.setString(i++, linked.version());
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
  public Optional<Anchor> anchor() {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
                  c.prepareStatement(
                      "SELECT head_hash, row_count, keyed_from_seq FROM agentguard_audit_anchor"
                          + " WHERE id = 1");
              ResultSet rs = ps.executeQuery()) {
            return rs.next()
                ? Optional.of(new Anchor(rs.getString(1), rs.getLong(2), (Long) rs.getObject(3)))
                : Optional.empty();
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
  public List<AuditEvent> latest(String tenantId, int limit) {
    if (tenantId == null) {
      return read(
          "SELECT " + COLUMNS + " FROM agentguard_audit WHERE seq > ? ORDER BY seq DESC LIMIT ?",
          0,
          limit);
    }
    return read(
        "SELECT "
            + COLUMNS
            + " FROM agentguard_audit WHERE seq > ? AND tenant_id = ? ORDER BY seq DESC LIMIT ?",
        0,
        limit,
        tenantId);
  }

  private List<AuditEvent> read(String sql, long after, int limit) {
    return read(sql, after, limit, null);
  }

  private List<AuditEvent> read(String sql, long after, int limit, String tenantId) {
    int capped = Math.max(1, Math.min(limit, 1000));
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps = c.prepareStatement(sql)) {
            int i = 1;
            ps.setLong(i++, after);
            if (tenantId != null) {
              ps.setString(i++, tenantId);
            }
            ps.setInt(i, capped);
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
        rs.getString("actor_id"),
        rs.getString("chain_version"),
        rs.getString("prev_hash"),
        rs.getString("hash"));
  }
}

package com.housedevinci.agentguard.adapter.jdbc;

import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.instant;
import static com.housedevinci.agentguard.adapter.jdbc.JdbcSupport.ts;

import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.AuditAnchor;
import com.housedevinci.agentguard.domain.AuditChain;
import com.housedevinci.agentguard.domain.AuditDecision;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.ErrorCodes;
import java.sql.Connection;
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
 *
 * <p>A trail is keyed from row 1 or unkeyed forever (design change, QUESTIONS.md #20:
 * "keyed-from-birth"): the anchor's {@code keyed} column records which, once, at the first append,
 * and is immutable afterwards. Every append after that — from this instance or any other — must
 * agree with it, or is refused with {@link ErrorCodes#AUDIT_KEY_MISMATCH}. A missing anchor on a
 * trail that already has rows is never re-derived by guessing from the trail head: it is refused
 * with {@link ErrorCodes#AUDIT_ANCHOR_MISSING}, both at construction and on every append, because a
 * guessed {@code keyed} value is exactly the thing the anchor exists to make unguessable.
 */
public final class JdbcAuditSink implements AuditSink, AuditReader, AuditAnchor {

  private static final String COLUMNS =
      "seq, ts, principal_id, tenant_id, tool, args_hash, result_hash, latency_ms, decision, "
          + "correlation_id, decision_id, actor_id, chain_version, key_id, prev_hash, hash";

  private final DataSource dataSource;
  private final AuditChain chain;

  public JdbcAuditSink(DataSource dataSource) {
    this(dataSource, AuditChain.unkeyed());
  }

  public JdbcAuditSink(DataSource dataSource, AuditChain chain) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    this.chain = Objects.requireNonNull(chain, "chain");
    // fail closed at startup, not only on the first append after it (a rolling restart must not be
    // able to serve traffic for a while before its first guarded call ever reaches append())
    JdbcSupport.withConnection(
        dataSource,
        c -> {
          refuseIfMismatched(currentTrailState(c));
          return null;
        });
  }

  /**
   * The anchor's {@code keyed} flag, or {@code null} when the trail is empty (anchor absent, no
   * rows yet — either mode is still legitimate, the first append decides it).
   */
  private record TrailState(boolean anchored, boolean keyed, boolean nonEmpty) {}

  private TrailState currentTrailState(Connection c) throws SQLException {
    try (PreparedStatement last =
            c.prepareStatement("SELECT keyed FROM agentguard_audit_anchor WHERE id = 1");
        ResultSet rs = last.executeQuery()) {
      if (rs.next()) {
        return new TrailState(true, rs.getBoolean(1), true);
      }
    }
    // no anchor row: refuse to guess if the trail already has rows (AUDIT_ANCHOR_MISSING); an
    // empty trail with no anchor is simply not started yet
    try (PreparedStatement head = c.prepareStatement("SELECT 1 FROM agentguard_audit LIMIT 1");
        ResultSet rs = head.executeQuery()) {
      return new TrailState(false, false, rs.next());
    }
  }

  private void refuseIfMismatched(TrailState state) {
    if (!state.anchored() && state.nonEmpty()) {
      throw new AgentGuardException(
          ErrorCodes.AUDIT_ANCHOR_MISSING,
          "agentguard_audit_anchor has no row but agentguard_audit is not empty. The schema seed"
              + " never invents a keyed value for rows it did not write, so this is refused rather"
              + " than guessed: either a restore lost the anchor row, or a role that can disable"
              + " triggers removed it. Remedy: start a new trail (archive agentguard_audit and"
              + " agentguard_audit_anchor — rename or drop them — and re-run the schema step so it"
              + " re-seeds an empty pair).");
    }
    if (state.anchored() && state.keyed() != chain.isKeyed()) {
      throw new AgentGuardException(
          ErrorCodes.AUDIT_KEY_MISMATCH,
          "agentguard_audit is "
              + (state.keyed() ? "keyed" : "unkeyed")
              + " but this instance is "
              + (chain.isKeyed() ? "keyed" : "unkeyed")
              + " (agentguard.audit.hmac-secret "
              + (chain.isKeyed() ? "is set" : "is not set, or agentguard.audit.unkeyed=true")
              + "). A trail is keyed from row 1 or unkeyed forever; it cannot switch. During a"
              + " rolling restart that changes agentguard.audit.hmac-secret, stop every instance"
              + " before starting the first one with the new setting. To change the audit mode for"
              + " real, start a new trail: archive agentguard_audit and agentguard_audit_anchor (a"
              + " new table, or a renamed/dropped one, so the schema step re-seeds it empty).");
    }
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
          boolean anchored = false;
          try (PreparedStatement last =
                  c.prepareStatement(
                      "SELECT head_hash, row_count, keyed FROM agentguard_audit_anchor"
                          + " WHERE id = 1");
              ResultSet rs = last.executeQuery()) {
            if (rs.next()) {
              prev = rs.getString(1);
              count = rs.getLong(2);
              refuseIfMismatched(new TrailState(true, rs.getBoolean(3), true));
              anchored = true;
            }
          }
          if (!anchored) {
            try (PreparedStatement head =
                    c.prepareStatement("SELECT 1 FROM agentguard_audit LIMIT 1");
                ResultSet rs = head.executeQuery()) {
              refuseIfMismatched(new TrailState(false, false, rs.next()));
            }
          }
          var linked = chain.linkEvent(event, prev);
          try (PreparedStatement anchor =
              c.prepareStatement(
                  "INSERT INTO agentguard_audit_anchor (id, head_hash, row_count, updated_at,"
                      + " keyed) VALUES (1, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET "
                      + "head_hash = EXCLUDED.head_hash, row_count = EXCLUDED.row_count, "
                      + "updated_at = EXCLUDED.updated_at")) {
            anchor.setString(1, linked.hash());
            anchor.setLong(2, count + 1);
            anchor.setObject(3, ts(linked.timestamp()));
            anchor.setBoolean(4, chain.isKeyed());
            anchor.executeUpdate();
          }
          try (PreparedStatement ps =
              c.prepareStatement(
                  "INSERT INTO agentguard_audit (ts, principal_id, tenant_id, tool, args_hash, "
                      + "result_hash, latency_ms, decision, correlation_id, decision_id, actor_id, "
                      + "chain_version, key_id, prev_hash, hash) "
                      + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq")) {
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
            ps.setString(i++, linked.keyId());
            ps.setString(i++, linked.prevHash());
            ps.setString(i, linked.hash());
            try (ResultSet rs = ps.executeQuery()) {
              rs.next();
              return linked.withSequence(rs.getLong(1));
            }
          }
        });
  }

  private static final long LOCK_KEY = 0x41474741554449L; // "AGGAUDI"

  @Override
  public Optional<Anchor> anchor() {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
                  c.prepareStatement(
                      "SELECT head_hash, row_count, keyed FROM agentguard_audit_anchor"
                          + " WHERE id = 1");
              ResultSet rs = ps.executeQuery()) {
            return rs.next()
                ? Optional.of(new Anchor(rs.getString(1), rs.getLong(2), rs.getBoolean(3)))
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
        rs.getString("key_id"),
        rs.getString("prev_hash"),
        rs.getString("hash"));
  }
}

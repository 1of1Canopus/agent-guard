package com.housedevinci.agentguard.domain;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

/**
 * One row of the append-only audit trail. {@code prevHash} and {@code hash} form the chain (see
 * {@link AuditChain}); they are null until the sink links the event. {@code actorId} is the human
 * or system that caused the row when it differs from the calling principal (the approver of an
 * APPROVED / REJECTED row). Timestamps are truncated to milliseconds so every store round-trips
 * them unchanged.
 */
public record AuditEvent(
    long sequence,
    Instant timestamp,
    String principalId,
    String tenantId,
    String tool,
    String argsHash,
    String resultHash,
    long latencyMillis,
    AuditDecision decision,
    String correlationId,
    String decisionId,
    String actorId,
    String prevHash,
    String hash) {

  public AuditEvent {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(principalId, "principalId");
    Objects.requireNonNull(tool, "tool");
    Objects.requireNonNull(decision, "decision");
    timestamp = timestamp.truncatedTo(ChronoUnit.MILLIS);
    argsHash = Objects.requireNonNullElse(argsHash, "");
    resultHash = Objects.requireNonNullElse(resultHash, "");
    correlationId = Objects.requireNonNullElse(correlationId, "");
  }

  public static Builder builder() {
    return new Builder();
  }

  public AuditEvent withDecision(AuditDecision d) {
    return new AuditEvent(
        sequence,
        timestamp,
        principalId,
        tenantId,
        tool,
        argsHash,
        resultHash,
        latencyMillis,
        d,
        correlationId,
        decisionId,
        actorId,
        prevHash,
        hash);
  }

  public AuditEvent withLatencyMillis(long l) {
    return new AuditEvent(
        sequence,
        timestamp,
        principalId,
        tenantId,
        tool,
        argsHash,
        resultHash,
        l,
        decision,
        correlationId,
        decisionId,
        actorId,
        prevHash,
        hash);
  }

  public AuditEvent withTool(String t) {
    return new AuditEvent(
        sequence,
        timestamp,
        principalId,
        tenantId,
        t,
        argsHash,
        resultHash,
        latencyMillis,
        decision,
        correlationId,
        decisionId,
        actorId,
        prevHash,
        hash);
  }

  public AuditEvent withSequence(long s) {
    return new AuditEvent(
        s,
        timestamp,
        principalId,
        tenantId,
        tool,
        argsHash,
        resultHash,
        latencyMillis,
        decision,
        correlationId,
        decisionId,
        actorId,
        prevHash,
        hash);
  }

  public AuditEvent withChain(String prev, String h) {
    return new AuditEvent(
        sequence,
        timestamp,
        principalId,
        tenantId,
        tool,
        argsHash,
        resultHash,
        latencyMillis,
        decision,
        correlationId,
        decisionId,
        actorId,
        prev,
        h);
  }

  /** Fluent builder; {@code sequence}, {@code prevHash} and {@code hash} are set by the sink. */
  public static final class Builder {
    private Instant timestamp;
    private String principalId;
    private String tenantId;
    private String tool;
    private String argsHash;
    private String resultHash;
    private long latencyMillis;
    private AuditDecision decision;
    private String correlationId;
    private String decisionId;
    private String actorId;

    public Builder timestamp(Instant v) {
      this.timestamp = v;
      return this;
    }

    public Builder principalId(String v) {
      this.principalId = v;
      return this;
    }

    public Builder tenantId(String v) {
      this.tenantId = v;
      return this;
    }

    public Builder tool(String v) {
      this.tool = v;
      return this;
    }

    public Builder argsHash(String v) {
      this.argsHash = v;
      return this;
    }

    public Builder resultHash(String v) {
      this.resultHash = v;
      return this;
    }

    public Builder latencyMillis(long v) {
      this.latencyMillis = v;
      return this;
    }

    public Builder decision(AuditDecision v) {
      this.decision = v;
      return this;
    }

    public Builder correlationId(String v) {
      this.correlationId = v;
      return this;
    }

    public Builder decisionId(String v) {
      this.decisionId = v;
      return this;
    }

    public Builder actorId(String v) {
      this.actorId = v;
      return this;
    }

    public AuditEvent build() {
      return new AuditEvent(
          0,
          timestamp,
          principalId,
          tenantId,
          tool,
          argsHash,
          resultHash,
          latencyMillis,
          decision,
          correlationId,
          decisionId,
          actorId,
          null,
          null);
    }
  }
}

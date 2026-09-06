package com.housedevinci.agentguard.domain;

/**
 * Append-only destination for audit events. The sink links the event into the hash chain and
 * assigns the sequence; callers pass an unlinked event.
 */
public interface AuditSink {
  AuditEvent append(AuditEvent event);
}

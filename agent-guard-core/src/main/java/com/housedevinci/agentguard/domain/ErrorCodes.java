package com.housedevinci.agentguard.domain;

/** Stable error codes returned to the model and documented in the docs page. */
public final class ErrorCodes {
  private ErrorCodes() {}

  /** Principal lacks a required role. */
  public static final String POLICY_ROLE = "AG-POLICY-001";

  /** Principal lacks a required scope. */
  public static final String POLICY_SCOPE = "AG-POLICY-002";

  /** Principal belongs to a tenant the tool is not enabled for. */
  public static final String POLICY_TENANT = "AG-POLICY-003";

  /** Tool has no policy and unregistered tools are denied. */
  public static final String POLICY_UNREGISTERED = "AG-POLICY-004";

  /** Call is parked, waiting for a human decision. */
  public static final String APPROVAL_PENDING = "AG-APPROVAL-001";

  /** Decision id unknown. */
  public static final String APPROVAL_NOT_FOUND = "AG-APPROVAL-002";

  /** Illegal state transition (e.g. reject after approve). */
  public static final String APPROVAL_ILLEGAL_TRANSITION = "AG-APPROVAL-003";

  /** Arguments changed between approval and execution. */
  public static final String APPROVAL_ARGS_TAMPERED = "AG-APPROVAL-004";

  /** Decision was rejected by a human. */
  public static final String APPROVAL_REJECTED = "AG-APPROVAL-005";

  /** Decision expired before a human decided. */
  public static final String APPROVAL_EXPIRED = "AG-APPROVAL-006";

  /** No executor registered for the tool at resume time. */
  public static final String APPROVAL_NO_EXECUTOR = "AG-APPROVAL-007";

  /** Too many decisions already waiting for this principal. */
  public static final String APPROVAL_TOO_MANY_PENDING = "AG-APPROVAL-008";

  /** Arguments too large to park. */
  public static final String APPROVAL_ARGS_TOO_LARGE = "AG-APPROVAL-009";

  /** The approver attested a different arguments hash than the decision carries. */
  public static final String APPROVAL_HASH_MISMATCH = "AG-APPROVAL-010";

  /** The parking principal tried to approve its own call. */
  public static final String APPROVAL_SELF = "AG-APPROVAL-011";

  /** A budget window is exhausted. */
  public static final String BUDGET_EXCEEDED = "AG-BUDGET-001";

  /**
   * A configured budget scope has no subject (no conversation id / tenant) and the policy denies.
   */
  public static final String BUDGET_SUBJECT_MISSING = "AG-BUDGET-002";

  /** The guard's own infrastructure (store, audit, notifier) failed; the call was not run. */
  public static final String GUARD_UNAVAILABLE = "AG-GUARD-001";

  /** The tool itself threw. */
  public static final String TOOL_FAILED = "AG-TOOL-001";

  /**
   * A trail is keyed from row 1 or unkeyed forever (no mixing). This sink's {@code
   * agentguard.audit.hmac-secret} (present or absent) does not match the trail's own keyed/unkeyed
   * state as recorded, once, on {@code agentguard_audit_anchor.keyed}. Refused rather than
   * appended, so a still-unkeyed instance mid rolling-restart cannot silently corrupt a keyed
   * trail, and a newly-keyed instance cannot silently start signing rows in a trail nothing else
   * ever keyed.
   */
  public static final String AUDIT_KEY_MISMATCH = "AG-AUDIT-001";

  /**
   * {@code agentguard_audit_anchor} has no row for a non-empty {@code agentguard_audit}. The schema
   * seed only ever creates the anchor row for an empty trail (it must never invent a {@code keyed}
   * value for rows it did not write); a missing anchor on a non-empty trail means the row was lost
   * after the trail was written, or this database predates the anchor and was never migrated while
   * empty. Refused rather than guessed, on both startup and every append.
   */
  public static final String AUDIT_ANCHOR_MISSING = "AG-AUDIT-002";

  /**
   * The audit trail's guards do not hold in the schema the application uses: one of the five
   * bundled triggers is missing, extra, disabled, not {@code ENABLE ALWAYS}, carries a {@code WHEN}
   * clause or a column list, or points at the wrong function; a guard body differs from the bundled
   * script; one of the four tables is not an ordinary, logged table ({@code UNLOGGED}, a view, a
   * partitioned table); or a rule, row level security, a policy or an inheritance edge exists on
   * one of the four tables. Refused at startup; no property downgrades it. Codes 001, 002, 004 and
   * 007 of this area are reserved for the schema verification of 0.2.0.
   */
  public static final String SCHEMA_UNGUARDED = "AG-SCHEMA-003";

  /**
   * The guard check could not complete: a catalogue read was refused, the connection failed, no
   * current schema resolved, the {@code search_path} pin did not take, or the bundled script did
   * not yield its three guard functions. Unverifiable is refused, never treated as clean.
   */
  public static final String SCHEMA_UNVERIFIABLE = "AG-SCHEMA-005";

  /**
   * {@code agentguard.jdbc.initialize-schema=true} and the bundled script failed, most commonly
   * because the application's role does not own the schema. Carries the SQLState only.
   */
  public static final String SCHEMA_CREATION_FAILED = "AG-SCHEMA-006";
}

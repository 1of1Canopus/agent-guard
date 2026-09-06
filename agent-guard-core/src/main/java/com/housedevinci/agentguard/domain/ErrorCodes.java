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
}

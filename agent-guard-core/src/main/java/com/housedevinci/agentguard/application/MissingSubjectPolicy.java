package com.housedevinci.agentguard.application;

/** What a budget does when its scope has no subject (no conversation id, no tenant). */
public enum MissingSubjectPolicy {
  /** Refuse the call (fail closed). */
  DENY,
  /** Count against the principal's counter for the same kind and window instead. */
  FALLBACK_TO_PRINCIPAL,
  /** Ignore that limit for this call. */
  SKIP
}

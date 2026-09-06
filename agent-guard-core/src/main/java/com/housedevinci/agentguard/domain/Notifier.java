package com.housedevinci.agentguard.domain;

/**
 * Tells a human that a call is waiting. Best effort: implementations MUST NOT throw for ordinary
 * delivery failures, the call is already parked and must stay parked.
 */
public interface Notifier {
  void notify(PendingDecision decision);
}

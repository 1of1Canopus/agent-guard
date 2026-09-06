package com.housedevinci.agentguard.domain;

/** What a tool does to the world. Drives the approval gate. */
public enum SideEffect {
  /** Reads data; never needs approval by default. */
  READ,
  /** Changes data reversibly. */
  WRITE,
  /** Changes data irreversibly (delete, pay, send). */
  DESTRUCTIVE
}

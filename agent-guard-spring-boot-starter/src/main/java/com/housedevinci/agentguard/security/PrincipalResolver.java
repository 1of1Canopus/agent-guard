package com.housedevinci.agentguard.security;

import com.housedevinci.agentguard.domain.Principal;

/** Who is calling right now. Provide your own bean to map API keys, MCP sessions, etc. */
@FunctionalInterface
public interface PrincipalResolver {
  Principal resolve();
}

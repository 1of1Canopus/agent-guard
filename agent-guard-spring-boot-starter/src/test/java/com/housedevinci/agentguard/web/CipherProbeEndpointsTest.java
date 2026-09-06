package com.housedevinci.agentguard.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolRef;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Cipher probe: the approval endpoints have no fail-closed check of their own. With the security
 * filter chain absent (no Spring Security on the classpath, a permitAll matcher, or a stdio /
 * internal deployment) an unauthenticated request approves and executes a parked DESTRUCTIVE call
 * as "anonymous".
 */
@SpringBootTest(
    properties = {
      "agentguard.enabled=true",
      "agentguard.store=MEMORY",
      "agentguard.endpoints.enabled=true",
      "spring.ai.mcp.server.enabled=false",
      "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration"
    },
    classes = CipherProbeEndpointsTest.App.class)
@AutoConfigureMockMvc(addFilters = false)
class CipherProbeEndpointsTest {

  @SpringBootConfiguration
  @EnableAutoConfiguration
  static class App {}

  @Autowired MockMvc mvc;
  @Autowired ApprovalService approvals;

  @Test
  void probe_anonymous_approver_is_accepted_when_no_filter_chain_protects_the_endpoint()
      throws Exception {
    var agent = new Principal("agent", Set.of("AGENT"), Set.of(), null);
    var d =
        approvals.park(
            new ToolInvocation(agent, "wipe_disk", "{\"all\":true}", null, null),
            new ToolRef("wipe_disk", SideEffect.DESTRUCTIVE),
            "{\"all\":true}");

    mvc.perform(get("/agentguard/decisions"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value(d.id().toString()));

    mvc.perform(post("/agentguard/decisions/" + d.id() + "/approve"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.decision.state").value("APPROVED"))
        .andExpect(jsonPath("$.decision.decidedBy").value("anonymous"))
        .andExpect(jsonPath("$.decision.executed").value(true));

    mvc.perform(get("/agentguard/audit")).andExpect(status().isOk());
  }
}

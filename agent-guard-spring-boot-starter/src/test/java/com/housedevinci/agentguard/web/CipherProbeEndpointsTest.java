package com.housedevinci.agentguard.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.domain.DecisionState;
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

/** the security review probe (M7), flipped: with no filter chain the endpoints refuse an anonymous approver. */
@SpringBootTest(
    properties = {
      "agentguard.enabled=true",
      "agentguard.audit.unkeyed=true",
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
  void anonymous_approver_is_refused_with_401_and_nothing_runs() throws Exception {
    var agent = new Principal("agent", Set.of("AGENT"), Set.of(), null);
    var d =
        approvals.park(
            new ToolInvocation(agent, "wipe_disk", "{\"all\":true}", null, null),
            new ToolRef("wipe_disk", SideEffect.DESTRUCTIVE),
            "{\"all\":true}");

    mvc.perform(get("/agentguard/decisions"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("AG-HTTP-401"));
    mvc.perform(
            post("/agentguard/decisions/" + d.id() + "/approve").param("argsHash", d.argsHash()))
        .andExpect(status().isUnauthorized());
    mvc.perform(post("/agentguard/decisions/" + d.id() + "/reject"))
        .andExpect(status().isUnauthorized());
    mvc.perform(get("/agentguard/decisions/" + d.id() + "/arguments"))
        .andExpect(status().isUnauthorized());
    mvc.perform(get("/agentguard/audit")).andExpect(status().isUnauthorized());

    var stored = approvals.find(d.id()).orElseThrow();
    assertThat(stored.state()).isEqualTo(DecisionState.PENDING);
    assertThat(stored.executed()).isFalse();
  }
}

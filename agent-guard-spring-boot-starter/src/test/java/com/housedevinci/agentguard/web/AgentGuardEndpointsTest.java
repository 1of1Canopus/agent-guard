package com.housedevinci.agentguard.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(
    properties = {
      "agentguard.enabled=true",
      "agentguard.store=MEMORY",
      "agentguard.endpoints.enabled=true",
      "spring.ai.mcp.server.enabled=false",
      "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration"
    },
    classes = AgentGuardEndpointsTest.App.class)
@AutoConfigureMockMvc
class AgentGuardEndpointsTest {

  @SpringBootConfiguration
  @EnableAutoConfiguration
  static class App {}

  @Autowired MockMvc mvc;
  @Autowired ApprovalService approvals;

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  private static void loginAs(String name) {
    var auth = new TestingAuthenticationToken(name, "n/a", "ROLE_APPROVER");
    auth.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(auth);
  }

  @Test
  void list_arguments_approve_reject_and_audit() throws Exception {
    loginAs("alice");
    var principal = new Principal("agent", Set.of("AGENT"), Set.of(), null);
    var d =
        approvals.park(
            new ToolInvocation(principal, "refund", "{\"amount\":5}", null, null),
            new ToolRef("refund", SideEffect.WRITE),
            "{\"amount\":5}");

    mvc.perform(get("/agentguard/decisions").with(user("alice").roles("APPROVER")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].id").value(d.id().toString()))
        .andExpect(jsonPath("$[0].argsPreview").value("{\"amount\":5}"))
        .andExpect(jsonPath("$[0].argumentsJson").doesNotExist());

    // approving requires the attested arguments hash
    mvc.perform(post("/agentguard/decisions/" + d.id() + "/approve").with(user("alice")))
        .andExpect(status().isBadRequest());
    mvc.perform(
            post("/agentguard/decisions/" + d.id() + "/approve")
                .param("argsHash", "0".repeat(64))
                .with(user("alice")))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("AG-APPROVAL-010"));

    mvc.perform(
            post("/agentguard/decisions/" + d.id() + "/approve")
                .param("argsHash", d.argsHash())
                .with(user("alice")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.decision.state").value("APPROVED"))
        .andExpect(jsonPath("$.decision.decidedBy").value("alice"))
        .andExpect(jsonPath("$.error").value(true)); // no executor captured in this bare context

    mvc.perform(post("/agentguard/decisions/" + d.id() + "/reject").with(user("bob")))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("AG-APPROVAL-003"));

    // the full redacted arguments are available to the approver, never the raw ones
    var d2 =
        approvals.park(
            new ToolInvocation(
                principal, "refund", "{\"amount\":6,\"password\":\"x\"}", null, null),
            new ToolRef("refund", SideEffect.WRITE),
            "p");
    mvc.perform(get("/agentguard/decisions/" + d2.id() + "/arguments").with(user("alice")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.argsHash").value(d2.argsHash()))
        .andExpect(jsonPath("$.arguments").value("{\"amount\":6,\"password\":\"***\"}"));

    mvc.perform(
            get("/agentguard/decisions/00000000-0000-0000-0000-000000000000").with(user("alice")))
        .andExpect(status().isNotFound());
    mvc.perform(get("/agentguard/decisions/not-a-uuid").with(user("alice")))
        .andExpect(status().isBadRequest());

    mvc.perform(get("/agentguard/audit").with(user("alice")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].decision").value("FAILED"))
        .andExpect(jsonPath("$[0].actorId").value("alice"))
        .andExpect(jsonPath("$[0].hash").isString());
    assertThat(approvals.find(d.id()).orElseThrow().executed()).isTrue();
  }
}

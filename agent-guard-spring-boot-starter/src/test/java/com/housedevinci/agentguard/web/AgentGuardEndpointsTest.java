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
      // list_arguments_approve_reject_and_audit exercises a deliberate cross-tenant approver
      // (no principal or approver in that test has a tenant); approvers_only_see_their_own_tenant
      // never logs in with a tenant-less approver, so this does not weaken its assertions (C9)
      "agentguard.endpoints.require-tenant=false",
      "spring.ai.mcp.server.enabled=false",
      "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration"
    },
    classes = {AgentGuardEndpointsTest.App.class, AgentGuardEndpointsTest.Tenants.class})
@AutoConfigureMockMvc
@org.springframework.test.annotation.DirtiesContext(
    classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AgentGuardEndpointsTest {

  @SpringBootConfiguration
  @EnableAutoConfiguration
  static class App {}

  @Autowired MockMvc mvc;
  @Autowired ApprovalService approvals;
  @Autowired com.housedevinci.agentguard.security.TenantResolver tenantResolver;
  @Autowired com.housedevinci.agentguard.security.PrincipalResolver principals;

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  private static void loginAs(String name) {
    var auth = new TestingAuthenticationToken(name, "n/a", "ROLE_APPROVER");
    auth.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(auth);
  }

  @org.springframework.boot.test.context.TestConfiguration
  static class Tenants {
    @org.springframework.context.annotation.Bean
    com.housedevinci.agentguard.security.TenantResolver tenantResolver() {
      return auth -> {
        String name = auth.getName();
        return name.startsWith("t1-")
            ? java.util.Optional.of("t1")
            : name.startsWith("t2-") ? java.util.Optional.of("t2") : java.util.Optional.empty();
      };
    }
  }

  @Test
  void approvers_only_see_their_own_tenant_and_cannot_approve_their_own_call() throws Exception {
    var t1Agent = new Principal("t1-agent", Set.of("AGENT"), Set.of(), "t1");
    var t2Agent = new Principal("t2-agent", Set.of("AGENT"), Set.of(), "t2");
    var d1 =
        approvals.park(
            new ToolInvocation(t1Agent, "refund", "{\"a\":1}", null, null),
            new ToolRef("refund", SideEffect.WRITE),
            "p");
    var d2 =
        approvals.park(
            new ToolInvocation(t2Agent, "refund", "{\"a\":2}", null, null),
            new ToolRef("refund", SideEffect.WRITE),
            "p");

    loginAs("t1-alice");
    mvc.perform(get("/agentguard/decisions").with(user("t1-alice")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(1))
        .andExpect(jsonPath("$[0].id").value(d1.id().toString()));
    mvc.perform(get("/agentguard/decisions/" + d2.id()).with(user("t1-alice")))
        .andExpect(status().isNotFound());
    mvc.perform(get("/agentguard/decisions/" + d2.id() + "/arguments").with(user("t1-alice")))
        .andExpect(status().isNotFound());
    mvc.perform(
            post("/agentguard/decisions/" + d2.id() + "/approve")
                .param("argsHash", d2.argsHash())
                .with(user("t1-alice")))
        .andExpect(status().isNotFound());
    mvc.perform(post("/agentguard/decisions/" + d2.id() + "/reject").with(user("t1-alice")))
        .andExpect(status().isNotFound());
    assertThat(approvals.find(d2.id()).orElseThrow().state().name()).isEqualTo("PENDING");

    // the parking principal may not decide its own call
    loginAs("t1-agent");
    mvc.perform(
            post("/agentguard/decisions/" + d1.id() + "/approve")
                .param("argsHash", d1.argsHash())
                .with(user("t1-agent")))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("AG-APPROVAL-011"));
    mvc.perform(post("/agentguard/decisions/" + d1.id() + "/reject").with(user("t1-agent")))
        .andExpect(status().isForbidden());

    loginAs("t2-bob");
    mvc.perform(post("/agentguard/decisions/" + d2.id() + "/reject").with(user("t2-bob")))
        .andExpect(status().isOk());
    mvc.perform(get("/agentguard/audit").with(user("t2-bob")))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$[*].tenantId")
                .value(org.hamcrest.Matchers.everyItem(org.hamcrest.Matchers.is("t2"))));
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

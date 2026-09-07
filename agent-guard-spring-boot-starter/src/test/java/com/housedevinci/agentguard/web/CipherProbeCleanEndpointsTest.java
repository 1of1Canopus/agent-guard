package com.housedevinci.agentguard.web;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolRef;
import java.util.Optional;
import java.util.Set;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Cipher probes for the clean-verdict pass on {@code 50ed8d3}: what tenant scoping (I4) does at its
 * edges. Each probe asserts today's behaviour; the fix flips it.
 */
@SpringBootTest(
    properties = {
      "agentguard.enabled=true",
      "agentguard.store=MEMORY",
      "agentguard.endpoints.enabled=true",
      "spring.ai.mcp.server.enabled=false",
      "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration"
    },
    classes = {
      CipherProbeCleanEndpointsTest.App.class,
      CipherProbeCleanEndpointsTest.Tenants.class
    })
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class CipherProbeCleanEndpointsTest {

  @SpringBootConfiguration
  @EnableAutoConfiguration
  static class App {}

  @TestConfiguration
  static class Tenants {
    @Bean
    com.housedevinci.agentguard.security.TenantResolver tenantResolver() {
      return auth ->
          auth.getName().startsWith("t1-")
              ? Optional.of("t1")
              : auth.getName().startsWith("t2-") ? Optional.of("t2") : Optional.empty();
    }
  }

  @Autowired MockMvc mvc;
  @Autowired ApprovalService approvals;

  @org.junit.jupiter.api.AfterEach
  void clear() {
    org.springframework.security.core.context.SecurityContextHolder.clearContext();
  }

  private static void loginAs(String name) {
    var auth =
        new org.springframework.security.authentication.TestingAuthenticationToken(
            name, "n/a", "ROLE_APPROVER");
    auth.setAuthenticated(true);
    org.springframework.security.core.context.SecurityContextHolder.getContext()
        .setAuthentication(auth);
  }

  private void park(String tenant, String args) {
    approvals.park(
        new ToolInvocation(
            new Principal(tenant + "-agent", Set.of("AGENT"), Set.of(), tenant),
            "refund",
            args,
            null,
            null),
        new ToolRef("refund", SideEffect.WRITE),
        "preview");
  }

  /**
   * C9: tenant scoping is applied only when the approver <em>has</em> a tenant. An approver whose
   * tenant claim is missing (a resolver that returns empty for a service account, a JWT without the
   * claim, a misconfigured {@code TenantResolver}) reads every tenant's decisions, argument
   * previews and audit rows, and can approve them. The scoping fails open.
   *
   * <p>Fix: {@code agentguard.endpoints.require-tenant} (default true when {@code tenant-scoped}):
   * an approver without a tenant gets 403 instead of everything; document the deliberate
   * cross-tenant approver as {@code require-tenant=false}.
   */
  @Test
  void probe_an_approver_without_a_tenant_reads_every_tenant() throws Exception {
    park("t1", "{\"a\":1}");
    park("t2", "{\"a\":2}");

    loginAs("nobody");
    mvc.perform(get("/agentguard/decisions").with(user("nobody")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(2));
  }

  /**
   * C10: {@code pending} and {@code audit} take the newest {@code limit} rows from the store and
   * only then drop the other tenants', so a busy neighbour hides a tenant's own pending approvals:
   * with three t2 decisions ahead of it, t1's approver asks for three rows and sees none of their
   * own. An approval inbox that silently omits work is an availability hole in the approval path.
   *
   * <p>Fix: push the tenant into the query — {@code DecisionStore.findByState(state, tenantId,
   * limit)} and {@code AuditReader.latest(tenantId, limit)} — instead of filtering the page.
   */
  @Test
  void probe_the_pending_inbox_is_filtered_after_the_store_limit() throws Exception {
    park("t2", "{\"a\":1}");
    park("t2", "{\"a\":2}");
    park("t2", "{\"a\":3}");
    park("t1", "{\"a\":4}");

    loginAs("t1-alice");
    mvc.perform(get("/agentguard/decisions").param("limit", "3").with(user("t1-alice")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(Matchers.lessThan(1)));
  }
}

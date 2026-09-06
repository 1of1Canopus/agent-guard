package com.housedevinci.agentguard.sample;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.housedevinci.agentguard.application.AuditChainVerifier;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** The SPEC acceptance check, end to end, through a real MCP client over streamable HTTP. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
class SampleEndToEndTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

  @LocalServerPort int port;
  @Autowired MockMvc mvc;
  @Autowired AuditChainVerifier verifier;

  private McpSyncClient clientAs(String user, String password) {
    var basic =
        "Basic "
            + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    var transport =
        HttpClientStreamableHttpTransport.builder("http://localhost:" + port)
            .endpoint("/mcp")
            .httpRequestCustomizer(
                (builder, method, uri, body, ctx) -> builder.header("Authorization", basic))
            .build();
    var client = McpClient.sync(transport).requestTimeout(Duration.ofSeconds(20)).build();
    client.initialize();
    return client;
  }

  private static String text(McpSchema.CallToolResult r) {
    return ((McpSchema.TextContent) r.content().get(0)).text();
  }

  @Test
  void read_allowed_write_parked_approve_once_budget_of_three_audit_chain() throws Exception {
    try (var agent = clientAs("agent", "agent")) {
      assertThat(agent.listTools().tools())
          .extracting(McpSchema.Tool::name)
          .containsExactlyInAnyOrder("get_order", "refund_order");

      // 1. read tool allowed
      var read =
          agent.callTool(new McpSchema.CallToolRequest("get_order", Map.of("orderId", "42")));
      assertThat(read.isError()).isNotEqualTo(Boolean.TRUE);
      assertThat(text(read)).contains("SHIPPED");

      // 2. write tool parked
      var parked =
          agent.callTool(new McpSchema.CallToolRequest("refund_order", Map.of("orderId", "42")));
      assertThat(parked.isError()).isTrue();
      assertThat(text(parked)).contains("AWAITING_APPROVAL").contains("decisionId");
      assertThat(
              agent.callTool(new McpSchema.CallToolRequest("get_order", Map.of("orderId", "42"))))
          .extracting(SampleEndToEndTest::text)
          .asString()
          .contains("SHIPPED");

      // 3. approval via endpoint resumes and executes once; second approval is a no-op
      var alice = SecurityMockMvcRequestPostProcessors.httpBasic("alice", "alice");
      var list =
          mvc.perform(get("/agentguard/decisions").with(alice))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$[0].tool").value("refund_order"))
              .andExpect(jsonPath("$[0].state").value("PENDING"))
              .andReturn()
              .getResponse()
              .getContentAsString();
      var id = list.replaceAll(".*\"id\":\"([0-9a-f-]{36})\".*", "$1");
      mvc.perform(post("/agentguard/decisions/" + id + "/approve").with(alice))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.decision.state").value("APPROVED"))
          .andExpect(jsonPath("$.decision.decidedBy").value("alice"))
          .andExpect(jsonPath("$.decision.executed").value(true))
          .andExpect(jsonPath("$.error").value(false));
      mvc.perform(post("/agentguard/decisions/" + id + "/approve").with(alice))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.decision.executed").value(true));
      mvc.perform(get("/agentguard/decisions").with(alice)).andExpect(jsonPath("$").isEmpty());
      // the agent is not allowed to approve
      mvc.perform(
              post("/agentguard/decisions/" + id + "/reject")
                  .with(SecurityMockMvcRequestPostProcessors.httpBasic("agent", "agent")))
          .andExpect(status().isForbidden());

      // 4. budget of 3 calls: this is the 4th within the minute
      var fourth =
          agent.callTool(new McpSchema.CallToolRequest("get_order", Map.of("orderId", "42")));
      assertThat(fourth.isError()).isTrue();
      assertThat(text(fourth)).contains("BUDGET_EXCEEDED").contains("AG-BUDGET-001");

      // 5. audit shows the chain, intact
      var audit =
          mvc.perform(get("/agentguard/audit").with(alice))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$[0].decision").value("BUDGET_EXCEEDED"))
              .andExpect(jsonPath("$[0].hash").isString())
              .andReturn()
              .getResponse()
              .getContentAsString();
      assertThat(audit)
          .contains("\"APPROVED\"")
          .contains("\"PENDING\"")
          .contains("\"ALLOWED\"")
          .contains("\"prevHash\"");
      assertThat(audit).doesNotContain("argumentsJson");
      assertThat(verifier.verify().intact()).isTrue();
      assertThat(verifier.verify().verified()).isGreaterThanOrEqualTo(5);
    }
    // anonymous MCP client is rejected by Spring Security
    var anon =
        HttpClientStreamableHttpTransport.builder("http://localhost:" + port)
            .endpoint("/mcp")
            .build();
    var client = McpClient.sync(anon).requestTimeout(Duration.ofSeconds(5)).build();
    org.assertj.core.api.Assertions.assertThatThrownBy(client::initialize)
        .isInstanceOf(RuntimeException.class);
    assertThat(List.of()).isEmpty();
  }
}

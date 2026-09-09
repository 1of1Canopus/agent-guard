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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * The SPEC acceptance check, end to end, through a real MCP client over streamable HTTP.
 *
 * <p>F9: {@code BudgetLimit} windows are epoch-aligned and tumbling ({@code windowStart =
 * floorDiv(now, size) * size}), so a test that reads the wall clock can have its four tool calls
 * straddle a window boundary and reset the budget counter mid-scenario - observed for real, once,
 * on a clean tree. The auto-configuration already exposes the seam: {@code
 * AgentGuardAutoConfiguration.agentGuardClock()} is {@code @ConditionalOnMissingBean(name =
 * "agentGuardClock")}, so a bean of that name defined here replaces it everywhere - the budget
 * store, the audit recorder, decision timestamps - with a clock this test controls instead of the
 * machine's. {@link #CLOCK} is pinned to an instant comfortably inside a one-minute window (30
 * seconds past the minute boundary) and never advanced during this test, so all four tool calls
 * land in the exact same budget window by construction, not by timing. No sleeps, no retries: the
 * assertion tests the budget rule, not the machine's speed. {@link MutableClock#advance} exists so
 * a future test of the window-rollover case itself (on purpose, rather than by accident) has
 * somewhere to start.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
class SampleEndToEndTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  /** A {@link Clock} whose instant is fixed until explicitly advanced. Not thread-hostile. */
  static final class MutableClock extends Clock {
    private final AtomicReference<Instant> now;
    private final ZoneId zone;

    MutableClock(Instant now, ZoneId zone) {
      this.now = new AtomicReference<>(now);
      this.zone = zone;
    }

    void advance(Duration by) {
      now.updateAndGet(i -> i.plus(by));
    }

    @Override
    public ZoneId getZone() {
      return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return new MutableClock(now.get(), zone);
    }

    @Override
    public Instant instant() {
      return now.get();
    }
  }

  @TestConfiguration
  static class FixedClockConfig {
    @Bean
    Clock agentGuardClock() {
      return CLOCK;
    }
  }

  // Any instant works, as long as it is not within a few seconds of a minute boundary: the
  // budget window under test is 1 minute (agent-guard-sample/src/main/resources/
  // application.yml, agentguard.budgets.limits[0].window). Pinned 30s past the minute so the
  // whole test body - which never advances the clock - runs inside one window regardless of
  // how long it actually takes on the machine.
  static final MutableClock CLOCK =
      new MutableClock(Instant.parse("2026-01-01T00:00:30Z"), ZoneId.of("UTC"));

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
          mvc.perform(
                  get("/agentguard/decisions")
                      .with(alice)
                      .with(SecurityMockMvcRequestPostProcessors.csrf()))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$[0].tool").value("refund_order"))
              .andExpect(jsonPath("$[0].state").value("PENDING"))
              .andReturn()
              .getResponse()
              .getContentAsString();
      var id = list.replaceAll(".*\"id\":\"([0-9a-f-]{36})\".*", "$1");
      var argsHash = list.replaceAll(".*\"argsHash\":\"([0-9a-f]{64})\".*", "$1");
      // the approver reads the full redacted arguments, then attests their hash
      mvc.perform(
              get("/agentguard/decisions/" + id + "/arguments")
                  .with(alice)
                  .with(SecurityMockMvcRequestPostProcessors.csrf()))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.arguments").value("{\"orderId\":\"42\"}"))
          .andExpect(jsonPath("$.argsHash").value(argsHash));
      mvc.perform(
              post("/agentguard/decisions/" + id + "/approve")
                  .param("argsHash", "f".repeat(64))
                  .with(alice)
                  .with(SecurityMockMvcRequestPostProcessors.csrf()))
          .andExpect(status().isConflict());
      mvc.perform(
              post("/agentguard/decisions/" + id + "/approve")
                  .param("argsHash", argsHash)
                  .with(alice)
                  .with(SecurityMockMvcRequestPostProcessors.csrf()))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.decision.state").value("APPROVED"))
          .andExpect(jsonPath("$.decision.decidedBy").value("alice"))
          .andExpect(jsonPath("$.decision.executed").value(true))
          .andExpect(jsonPath("$.error").value(false));
      mvc.perform(
              post("/agentguard/decisions/" + id + "/approve")
                  .param("argsHash", argsHash)
                  .with(alice)
                  .with(SecurityMockMvcRequestPostProcessors.csrf()))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.decision.executed").value(true));
      mvc.perform(
              get("/agentguard/decisions")
                  .with(alice)
                  .with(SecurityMockMvcRequestPostProcessors.csrf()))
          .andExpect(jsonPath("$").isEmpty());
      // the agent is not allowed to approve
      mvc.perform(
              post("/agentguard/decisions/" + id + "/reject")
                  .with(SecurityMockMvcRequestPostProcessors.httpBasic("agent", "agent"))
                  .with(SecurityMockMvcRequestPostProcessors.csrf()))
          .andExpect(status().isForbidden());

      // 4. budget of 3 calls: read, parked write, read = 3; the approved execution is not charged
      //    again, so this read is the 4th call within the minute
      var fourth =
          agent.callTool(new McpSchema.CallToolRequest("get_order", Map.of("orderId", "42")));
      assertThat(fourth.isError()).isTrue();
      assertThat(text(fourth)).contains("BUDGET_EXCEEDED").contains("AG-BUDGET-001");

      // 5. audit shows the chain, intact
      var audit =
          mvc.perform(
                  get("/agentguard/audit")
                      .with(alice)
                      .with(SecurityMockMvcRequestPostProcessors.csrf()))
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
          .contains("\"prevHash\"")
          .contains("\"actorId\":\"alice\"");
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

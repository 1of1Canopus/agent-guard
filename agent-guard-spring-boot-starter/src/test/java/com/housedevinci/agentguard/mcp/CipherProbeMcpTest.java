package com.housedevinci.agentguard.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.SideEffect;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.spring.SyncMcpAnnotationProviders;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import reactor.core.publisher.Mono;

/** Cipher probes for the MCP integration seam. */
class CipherProbeMcpTest {

  static final AtomicInteger DIRECT = new AtomicInteger();

  static class Tools {
    @McpTool(
        name = "get_weather",
        description = "read",
        annotations = @McpTool.McpAnnotations(readOnlyHint = true))
    public String weather(String city) {
      return "sunny in " + city;
    }

    @McpTool(name = "delete_account", description = "write")
    @ToolPolicy(roles = "ADMIN", sideEffect = SideEffect.DESTRUCTIVE)
    public String delete(String id) {
      return "deleted " + id;
    }
  }

  private static McpSchema.CallToolResult direct(String text) {
    DIRECT.incrementAndGet();
    return McpSchema.CallToolResult.builder().addTextContent(text).isError(false).build();
  }

  @Configuration(proxyBeanMethods = false)
  static class SpecsConfig {
    @Bean
    Tools tools() {
      return new Tools();
    }

    @Bean
    List<McpServerFeatures.SyncToolSpecification> toolSpecs(Tools tools) {
      return SyncMcpAnnotationProviders.toolSpecifications(List.of(tools));
    }

    /** A hand-written specification bean, the SDK's own API, not in a List. */
    @Bean
    McpServerFeatures.SyncToolSpecification wipeDisk() {
      var tool = McpSchema.Tool.builder().name("wipe_disk").inputSchema(Map.of()).build();
      return new McpServerFeatures.SyncToolSpecification(
          tool, (exchange, request) -> direct("wiped"));
    }

    /** What a WebFlux (async) MCP server publishes. */
    @Bean
    List<McpServerFeatures.AsyncToolSpecification> asyncSpecs() {
      var tool = McpSchema.Tool.builder().name("drop_database").inputSchema(Map.of()).build();
      return List.of(
          new McpServerFeatures.AsyncToolSpecification(
              tool, (exchange, request) -> Mono.just(direct("dropped"))));
    }
  }

  static final class BrokenAudit implements AuditSink, AuditReader {
    @Override
    public AuditEvent append(AuditEvent event) {
      throw new IllegalStateException(
          "Agent Guard JDBC failure: Connection to db.internal:5432 refused (user agentguard)");
    }

    @Override
    public List<AuditEvent> readAfter(long afterSequence, int limit) {
      return List.of();
    }

    @Override
    public List<AuditEvent> latest(int limit) {
      return List.of();
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class BrokenAuditConfig {
    @Bean
    BrokenAudit brokenAudit() {
      return new BrokenAudit();
    }
  }

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  AgentGuardAutoConfiguration.class, AgentGuardMcpAutoConfiguration.class))
          .withUserConfiguration(SpecsConfig.class)
          .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY");

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  private static void loginAs(String user, String role) {
    var auth =
        new TestingAuthenticationToken(
            user, "n/a", List.of(new SimpleGrantedAuthority("ROLE_" + role)));
    auth.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(auth);
  }

  @SuppressWarnings("unchecked")
  private static McpServerFeatures.SyncToolSpecification spec(List<?> specs, String tool) {
    return ((List<McpServerFeatures.SyncToolSpecification>) specs)
        .stream().filter(s -> s.tool().name().equals(tool)).findFirst().orElseThrow();
  }

  private static String text(McpSchema.CallToolResult r) {
    return ((McpSchema.TextContent) r.content().get(0)).text();
  }

  @Test
  void probe_client_controlled_meta_conversation_id_defeats_the_steps_budget() {
    runner
        .withPropertyValues(
            "agentguard.budgets.limits[0].scope=CONVERSATION",
            "agentguard.budgets.limits[0].kind=STEPS",
            "agentguard.budgets.limits[0].window=PT1H",
            "agentguard.budgets.limits[0].limit=2")
        .run(
            ctx -> {
              var weather = spec(ctx.getBean("toolSpecs", List.class), "get_weather");
              loginAs("bob", "USER");
              for (int i = 0; i < 5; i++) {
                // no _meta at all
                var r =
                    weather
                        .callHandler()
                        .apply(
                            null,
                            new McpSchema.CallToolRequest("get_weather", Map.of("city", "Paris")));
                assertThat(r.isError()).isNotEqualTo(Boolean.TRUE);
                // a fresh _meta id every call
                var r2 =
                    weather
                        .callHandler()
                        .apply(
                            null,
                            new McpSchema.CallToolRequest(
                                "get_weather",
                                Map.of("city", "Paris"),
                                Map.of("agentguard.conversationId", "c" + i)));
                assertThat(r2.isError()).isNotEqualTo(Boolean.TRUE);
              }
              // control: honest client with a stable id hits the cap on the 3rd step
              McpSchema.CallToolResult last = null;
              for (int i = 0; i < 3; i++) {
                last =
                    weather
                        .callHandler()
                        .apply(
                            null,
                            new McpSchema.CallToolRequest(
                                "get_weather",
                                Map.of("city", "Paris"),
                                Map.of("agentguard.conversationId", "stable")));
              }
              assertThat(text(last)).contains("AG-BUDGET-001");
            });
  }

  @Test
  void probe_single_spec_beans_and_async_spec_lists_are_silently_unguarded() {
    runner.run(
        ctx -> {
          DIRECT.set(0);
          SecurityContextHolder.clearContext(); // anonymous caller

          var single = ctx.getBean("wipeDisk", McpServerFeatures.SyncToolSpecification.class);
          var r =
              single
                  .callHandler()
                  .apply(null, new McpSchema.CallToolRequest("wipe_disk", Map.of()));
          assertThat(text(r)).isEqualTo("wiped");

          @SuppressWarnings("unchecked")
          var async =
              (List<McpServerFeatures.AsyncToolSpecification>)
                  ctx.getBean("asyncSpecs", List.class);
          var r2 =
              async
                  .get(0)
                  .callHandler()
                  .apply(null, new McpSchema.CallToolRequest("drop_database", Map.of()))
                  .block();
          assertThat(text(r2)).isEqualTo("dropped");

          assertThat(DIRECT).hasValue(2);
          assertThat(ctx.getBean(AuditReader.class).latest(10)).isEmpty();
        });
  }

  @Test
  void probe_guard_infrastructure_failure_escapes_as_a_raw_exception_to_the_mcp_layer() {
    runner
        .withUserConfiguration(BrokenAuditConfig.class)
        .run(
            ctx -> {
              var weather = spec(ctx.getBean("toolSpecs", List.class), "get_weather");
              loginAs("bob", "USER");
              // McpServerSession maps this to JSON-RPC error {code:-32603, message: getMessage()}
              assertThatThrownBy(
                      () ->
                          weather
                              .callHandler()
                              .apply(
                                  null,
                                  new McpSchema.CallToolRequest(
                                      "get_weather", Map.of("city", "x"))))
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("db.internal:5432");
            });
  }
}

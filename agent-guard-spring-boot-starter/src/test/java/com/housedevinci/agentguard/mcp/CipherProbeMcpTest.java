package com.housedevinci.agentguard.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.AuditSink;
import com.housedevinci.agentguard.domain.SideEffect;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServerExchange;
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

/** Cipher probes for the MCP integration seam, flipped: H2, M3 and M6 are fixed. */
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
  }

  @Configuration(proxyBeanMethods = false)
  static class AsyncSpecsConfig {
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
    public List<AuditEvent> latest(String tenantId, int limit) {
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

  private static McpSyncServerExchange session(String id) {
    var exchange = mock(McpSyncServerExchange.class);
    when(exchange.sessionId()).thenReturn(id);
    return exchange;
  }

  @Test // M3 flipped: the conversation is the server-side session; client _meta is ignored; absent
  // = denied
  void steps_budget_uses_the_server_side_session_id() {
    runner
        .withPropertyValues(
            "agentguard.budgets.limits[0].scope=CONVERSATION",
                "agentguard.budgets.limits[0].kind=STEPS",
            "agentguard.budgets.limits[0].window=PT1H", "agentguard.budgets.limits[0].limit=2")
        .run(
            ctx -> {
              var weather = spec(ctx.getBean("toolSpecs", List.class), "get_weather");
              loginAs("bob", "USER");
              // no session (stateless / unknown): fail closed under strict
              var none =
                  weather
                      .callHandler()
                      .apply(
                          null,
                          new McpSchema.CallToolRequest("get_weather", Map.of("city", "Paris")));
              assertThat(none.isError()).isTrue();
              assertThat(text(none)).contains("AG-BUDGET-002");
              // a rotating client _meta id does not help: the session decides
              var session = session("session-1");
              McpSchema.CallToolResult last = null;
              for (int i = 0; i < 3; i++) {
                last =
                    weather
                        .callHandler()
                        .apply(
                            session,
                            new McpSchema.CallToolRequest(
                                "get_weather",
                                Map.of("city", "Paris"),
                                Map.of("agentguard.conversationId", "c" + i)));
              }
              assertThat(last.isError()).isTrue();
              assertThat(text(last)).contains("AG-BUDGET-001");
              // another session has its own counter
              var other =
                  weather
                      .callHandler()
                      .apply(
                          session("session-2"),
                          new McpSchema.CallToolRequest("get_weather", Map.of("city", "Paris")));
              assertThat(other.isError()).isNotEqualTo(Boolean.TRUE);
            });
  }

  @Test // H2 flipped: single spec beans are guarded, async specs refuse to start
  void single_spec_beans_are_guarded_and_async_specs_fail_startup() {
    runner.run(
        ctx -> {
          DIRECT.set(0);
          SecurityContextHolder.clearContext();
          var single = ctx.getBean("wipeDisk", McpServerFeatures.SyncToolSpecification.class);
          var r =
              single
                  .callHandler()
                  .apply(null, new McpSchema.CallToolRequest("wipe_disk", Map.of()));
          assertThat(r.isError()).isTrue();
          assertThat(text(r)).contains("AG-POLICY-004");
          assertThat(DIRECT).hasValue(0);
          assertThat(ctx.getBean(AuditReader.class).latest(10))
              .extracting(e -> e.decision().name())
              .containsExactly("DENIED");
        });
    runner
        .withUserConfiguration(AsyncSpecsConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .hasMessageContaining("async MCP tool specifications");
            });
  }

  @Test // M6 flipped
  void guard_infrastructure_failure_is_a_structured_error_result() {
    runner
        .withUserConfiguration(BrokenAuditConfig.class)
        .run(
            ctx -> {
              var weather = spec(ctx.getBean("toolSpecs", List.class), "get_weather");
              loginAs("bob", "USER");
              var r =
                  weather
                      .callHandler()
                      .apply(
                          session("s"),
                          new McpSchema.CallToolRequest("get_weather", Map.of("city", "x")));
              assertThat(r.isError()).isTrue();
              assertThat(text(r))
                  .contains("AG-GUARD-001")
                  .contains("correlationId")
                  .doesNotContain("db.internal");
            });
  }

  @Test // strict coverage: an @McpTool with a policy that no server publishes fails startup
  void strict_mode_refuses_unguarded_policies() {
    new ApplicationContextRunner()
        .withConfiguration(
            AutoConfigurations.of(
                AgentGuardAutoConfiguration.class, AgentGuardMcpAutoConfiguration.class))
        .withBean(Tools.class)
        .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              Throwable t = ctx.getStartupFailure();
              while (t.getCause() != null) {
                t = t.getCause();
              }
              assertThat(t)
                  .hasMessageContaining("delete_account")
                  .hasMessageContaining("agentguard.strict");
            });
    new ApplicationContextRunner()
        .withConfiguration(
            AutoConfigurations.of(
                AgentGuardAutoConfiguration.class, AgentGuardMcpAutoConfiguration.class))
        .withBean(Tools.class)
        .withPropertyValues(
            "agentguard.enabled=true", "agentguard.store=MEMORY", "agentguard.strict=false")
        .run(ctx -> assertThat(ctx).hasNotFailed());
  }
}

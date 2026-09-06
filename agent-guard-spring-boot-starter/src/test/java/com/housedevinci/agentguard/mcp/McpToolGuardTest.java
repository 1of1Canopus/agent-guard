package com.housedevinci.agentguard.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.autoconfigure.AgentGuardAutoConfiguration;
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

class McpToolGuardTest {

  static final AtomicInteger DELETES = new AtomicInteger();

  static class Tools {
    @McpTool(name = "get_weather", description = "read", annotations = @McpTool.McpAnnotations(readOnlyHint = true))
    public String weather(String city) {
      return "sunny in " + city;
    }

    @McpTool(name = "delete_account", description = "write")
    @ToolPolicy(roles = "ADMIN", sideEffect = SideEffect.DESTRUCTIVE)
    public String delete(String id) {
      DELETES.incrementAndGet();
      return "deleted " + id;
    }

    @McpTool(name = "mystery", description = "unannotated, not read-only")
    public String mystery() {
      return "?";
    }
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
  }

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(AgentGuardAutoConfiguration.class, AgentGuardMcpAutoConfiguration.class))
          .withUserConfiguration(SpecsConfig.class)
          .withPropertyValues("agentguard.enabled=true", "agentguard.store=MEMORY");

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  private static void loginAs(String user, String role) {
    var auth = new TestingAuthenticationToken(user, "n/a", List.of(new SimpleGrantedAuthority("ROLE_" + role)));
    auth.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(auth);
  }

  @SuppressWarnings("unchecked")
  private static McpSchema.CallToolResult call(List<?> specs, String tool, Map<String, Object> args) {
    var spec = ((List<McpServerFeatures.SyncToolSpecification>) specs).stream().filter(s -> s.tool().name().equals(tool)).findFirst().orElseThrow();
    return spec.callHandler().apply(null, new McpSchema.CallToolRequest(tool, args));
  }

  private static String text(McpSchema.CallToolResult r) {
    return ((McpSchema.TextContent) r.content().get(0)).text();
  }

  @Test
  void tool_spec_list_beans_are_wrapped_and_guarded() {
    runner.run(
        ctx -> {
          DELETES.set(0);
          var specs = ctx.getBean("toolSpecs", List.class);
          loginAs("bob", "USER");

          var weather = call(specs, "get_weather", Map.of("city", "Paris"));
          assertThat(weather.isError()).isNotEqualTo(Boolean.TRUE);
          assertThat(text(weather)).contains("sunny in Paris");

          var mystery = call(specs, "mystery", Map.of());
          assertThat(mystery.isError()).isTrue();
          assertThat(text(mystery)).contains("AG-POLICY-004");

          var denied = call(specs, "delete_account", Map.of("id", "7"));
          assertThat(denied.isError()).isTrue();
          assertThat(text(denied)).contains("AG-POLICY-001");

          loginAs("root", "ADMIN");
          var parked = call(specs, "delete_account", Map.of("id", "7"));
          assertThat(parked.isError()).isTrue();
          assertThat(text(parked)).contains("AWAITING_APPROVAL");
          assertThat(DELETES).hasValue(0);

          var approvals = ctx.getBean(ApprovalService.class);
          var id = approvals.pending(10).get(0).id();
          var outcome = approvals.approve(id, "alice");
          assertThat(outcome.result().isError()).isFalse();
          assertThat(outcome.result().toModelText()).contains("deleted 7");
          assertThat(DELETES).hasValue(1);

          // the MCP client re-calls: replayed CallToolResult, no second delete
          var replay = call(specs, "delete_account", Map.of("id", "7"));
          assertThat(replay.isError()).isNotEqualTo(Boolean.TRUE);
          assertThat(text(replay)).contains("deleted 7");
          assertThat(DELETES).hasValue(1);
        });
  }

  @Test
  void hint_only_honours_read_only() {
    var readOnly = McpSchema.Tool.builder().name("a").inputSchema(Map.of()).annotations(new McpSchema.ToolAnnotations("t", true, null, null, null, null)).build();
    var destructive = McpSchema.Tool.builder().name("b").inputSchema(Map.of()).annotations(new McpSchema.ToolAnnotations("t", false, true, null, null, null)).build();
    var none = McpSchema.Tool.builder().name("c").inputSchema(Map.of()).build();
    assertThat(McpToolGuard.hint(readOnly)).contains(SideEffect.READ);
    assertThat(McpToolGuard.hint(destructive)).isEmpty();
    assertThat(McpToolGuard.hint(none)).isEmpty();
  }
}

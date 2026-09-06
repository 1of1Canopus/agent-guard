package com.housedevinci.agentguard.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolPolicyRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.tool.annotation.Tool;

class ToolPolicyAnnotationScannerTest {

  static class Tools {
    @McpTool(name = "lookup_order", description = "d")
    @ToolPolicy(roles = "SUPPORT")
    public String lookup(String id) {
      return id;
    }

    @Tool(description = "d")
    @ToolPolicy(
        roles = {"SUPPORT", "ADMIN"},
        scopes = "orders:write",
        tenants = "acme",
        sideEffect = SideEffect.DESTRUCTIVE)
    public String refund(String id) {
      return id;
    }

    @McpTool(description = "no policy")
    public String plain() {
      return "x";
    }
  }

  @Test
  void registers_rules_under_the_tool_name() {
    var registry = new ToolPolicyRegistry();
    new ToolPolicyAnnotationScanner(registry).postProcessAfterInitialization(new Tools(), "tools");
    assertThat(registry.find("lookup_order")).isPresent();
    assertThat(registry.find("lookup_order").get().roles()).containsExactly("SUPPORT");
    var refund = registry.find("refund").orElseThrow();
    assertThat(refund.roles()).containsExactlyInAnyOrder("SUPPORT", "ADMIN");
    assertThat(refund.scopes()).containsExactly("orders:write");
    assertThat(refund.tenants()).containsExactly("acme");
    assertThat(refund.sideEffect()).isEqualTo(SideEffect.DESTRUCTIVE);
    assertThat(registry.find("plain")).isEmpty();
    assertThat(registry.find("lookup")).isEmpty();
  }
}

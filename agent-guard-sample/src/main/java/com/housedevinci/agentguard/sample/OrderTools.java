package com.housedevinci.agentguard.sample;

import com.housedevinci.agentguard.api.ToolPolicy;
import com.housedevinci.agentguard.domain.SideEffect;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

@Component
public class OrderTools {

  private final Map<String, String> orders = new ConcurrentHashMap<>(Map.of("42", "SHIPPED"));

  @McpTool(
      name = "get_order",
      title = "Get order status",
      description = "Status of an order by its id: SHIPPED, REFUNDED or UNKNOWN. Reads only.",
      annotations =
          @McpTool.McpAnnotations(
              readOnlyHint = true,
              destructiveHint = false,
              idempotentHint = true,
              openWorldHint = false))
  @ToolPolicy(roles = "AGENT")
  public String getOrder(@McpToolParam(description = "order id") String orderId) {
    return orders.getOrDefault(orderId, "UNKNOWN");
  }

  @McpTool(
      name = "refund_order",
      title = "Refund order",
      description =
          "Refund an order by its id (needs a human). The call is parked until an approver"
              + " approves it, then runs once.",
      annotations =
          @McpTool.McpAnnotations(
              readOnlyHint = false,
              destructiveHint = true,
              idempotentHint = false,
              openWorldHint = false))
  @ToolPolicy(roles = "AGENT", sideEffect = SideEffect.WRITE)
  public String refundOrder(@McpToolParam(description = "order id") String orderId) {
    orders.put(orderId, "REFUNDED");
    return "refunded " + orderId;
  }
}

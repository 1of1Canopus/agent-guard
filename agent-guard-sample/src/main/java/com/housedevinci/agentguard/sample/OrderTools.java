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

  @McpTool(name = "get_order", description = "Status of an order")
  @ToolPolicy(roles = "AGENT")
  public String getOrder(@McpToolParam(description = "order id") String orderId) {
    return orders.getOrDefault(orderId, "UNKNOWN");
  }

  @McpTool(name = "refund_order", description = "Refund an order (needs a human)")
  @ToolPolicy(roles = "AGENT", sideEffect = SideEffect.WRITE)
  public String refundOrder(@McpToolParam(description = "order id") String orderId) {
    orders.put(orderId, "REFUNDED");
    return "refunded " + orderId;
  }
}

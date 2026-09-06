package com.housedevinci.agentguard.mcp;

import com.housedevinci.agentguard.application.GuardResult;
import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.security.PrincipalResolver;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpStatelessServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import tools.jackson.databind.json.JsonMapper;

/**
 * Wraps MCP tool specifications (the {@code @McpTool} path) so their {@code callHandler} goes
 * through the {@link ToolGuard}. Refusals become {@code CallToolResult(isError=true)} with the
 * structured JSON text, never an exception.
 */
public final class McpToolGuard {

  private final ToolGuard guard;
  private final PrincipalResolver principals;
  private final JsonMapper json;

  public McpToolGuard(ToolGuard guard, PrincipalResolver principals, JsonMapper json) {
    this.guard = guard;
    this.principals = principals;
    this.json = json;
  }

  public McpServerFeatures.SyncToolSpecification guard(
      McpServerFeatures.SyncToolSpecification spec) {
    var hint = hint(spec.tool());
    return new McpServerFeatures.SyncToolSpecification(
        spec.tool(),
        (exchange, request) ->
            run(spec.tool(), request, hint, args -> spec.callHandler().apply(exchange, args)));
  }

  public McpStatelessServerFeatures.SyncToolSpecification guard(
      McpStatelessServerFeatures.SyncToolSpecification spec) {
    var hint = hint(spec.tool());
    return new McpStatelessServerFeatures.SyncToolSpecification(
        spec.tool(),
        (ctx, request) ->
            run(spec.tool(), request, hint, args -> spec.callHandler().apply(ctx, args)));
  }

  private McpSchema.CallToolResult run(
      McpSchema.Tool tool,
      McpSchema.CallToolRequest request,
      Optional<SideEffect> hint,
      Function<McpSchema.CallToolRequest, McpSchema.CallToolResult> delegate) {
    Map<String, Object> arguments = request.arguments() == null ? Map.of() : request.arguments();
    String argsJson = json.writeValueAsString(arguments);
    var invocation =
        new ToolInvocation(
            principals.resolve(), tool.name(), argsJson, conversationId(request), null);
    var holder = new McpSchema.CallToolResult[1];
    GuardResult result =
        guard.execute(
            invocation,
            hint,
            args -> {
              // args == argsJson on the direct path; on resume they come from the store
              Map<String, Object> parsed =
                  json.readValue(
                      args, new tools.jackson.core.type.TypeReference<Map<String, Object>>() {});
              var r =
                  delegate.apply(
                      new McpSchema.CallToolRequest(request.name(), parsed, request.meta()));
              holder[0] = r;
              if (Boolean.TRUE.equals(r.isError())) {
                throw new McpToolException(text(r));
              }
              return json.writeValueAsString(r);
            });
    if (result instanceof GuardResult.Executed && holder[0] != null) {
      return holder[0];
    }
    if (result instanceof GuardResult.Executed executed) {
      // resumed from a stored result: replay the serialised CallToolResult
      try {
        return json.readValue(executed.result(), McpSchema.CallToolResult.class);
      } catch (RuntimeException e) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(executed.result())
            .isError(false)
            .build();
      }
    }
    return McpSchema.CallToolResult.builder()
        .addTextContent(result.toModelText())
        .isError(true)
        .build();
  }

  static Optional<SideEffect> hint(McpSchema.Tool tool) {
    var a = tool.annotations();
    if (a != null && Boolean.TRUE.equals(a.readOnlyHint())) {
      return Optional.of(SideEffect.READ);
    }
    return Optional.empty();
  }

  private static String conversationId(McpSchema.CallToolRequest request) {
    if (request.meta() == null) {
      return null;
    }
    Object v = request.meta().get("agentguard.conversationId");
    return v == null ? null : v.toString();
  }

  private static String text(McpSchema.CallToolResult r) {
    if (r.content() == null) {
      return "tool error";
    }
    return r.content().stream()
        .filter(c -> c instanceof McpSchema.TextContent)
        .map(c -> ((McpSchema.TextContent) c).text())
        .findFirst()
        .orElse("tool error");
  }

  /** The delegate reported {@code isError=true}. */
  static final class McpToolException extends RuntimeException {
    McpToolException(String message) {
      super(message);
    }
  }

  /** Utility for the bean post-processor: wraps a list if it holds tool specifications. */
  @SuppressWarnings("unchecked")
  Object guardListIfApplicable(Object bean) {
    if (!(bean instanceof List<?> list) || list.isEmpty()) {
      return bean;
    }
    if (list.stream().allMatch(e -> e instanceof McpServerFeatures.SyncToolSpecification)) {
      return ((List<McpServerFeatures.SyncToolSpecification>) list)
          .stream().map(this::guard).toList();
    }
    if (list.stream()
        .allMatch(e -> e instanceof McpStatelessServerFeatures.SyncToolSpecification)) {
      return ((List<McpStatelessServerFeatures.SyncToolSpecification>) list)
          .stream().map(this::guard).toList();
    }
    return bean;
  }
}

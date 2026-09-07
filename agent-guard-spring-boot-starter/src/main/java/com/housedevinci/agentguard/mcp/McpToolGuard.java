package com.housedevinci.agentguard.mcp;

import com.housedevinci.agentguard.application.GuardResult;
import com.housedevinci.agentguard.application.ToolGuard;
import com.housedevinci.agentguard.application.ToolInvocation;
import com.housedevinci.agentguard.autoconfigure.AgentGuardConfigurationException;
import com.housedevinci.agentguard.autoconfigure.GuardCoverage;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.security.PrincipalResolver;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpStatelessServerFeatures;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.json.JsonMapper;

/**
 * Wraps MCP tool specifications (the {@code @McpTool} path) so their {@code callHandler} goes
 * through the {@link ToolGuard}. Refusals become {@code CallToolResult(isError=true)} with the
 * structured JSON text, never an exception. The conversation id is the server-side MCP session id;
 * client-supplied {@code _meta} is never trusted for budgets. The exchange of the parking call is
 * captured with the decision.
 */
public final class McpToolGuard {

  private static final Logger log = LoggerFactory.getLogger(McpToolGuard.class);

  private final ToolGuard guard;
  private final PrincipalResolver principals;
  private final JsonMapper json;
  private final GuardCoverage coverage;

  public McpToolGuard(
      ToolGuard guard, PrincipalResolver principals, JsonMapper json, GuardCoverage coverage) {
    this.guard = guard;
    this.principals = principals;
    this.json = json;
    this.coverage = coverage;
  }

  public McpServerFeatures.SyncToolSpecification guard(
      McpServerFeatures.SyncToolSpecification spec) {
    var hint = hint(spec.tool());
    coverage.guarded(spec.tool().name(), GuardCoverage.Path.MCP);
    return new McpServerFeatures.SyncToolSpecification(
        spec.tool(),
        (exchange, request) ->
            run(
                spec.tool(),
                request,
                sessionId(exchange),
                hint,
                args -> spec.callHandler().apply(exchange, args)));
  }

  public McpStatelessServerFeatures.SyncToolSpecification guard(
      McpStatelessServerFeatures.SyncToolSpecification spec) {
    var hint = hint(spec.tool());
    coverage.guarded(spec.tool().name(), GuardCoverage.Path.MCP);
    return new McpStatelessServerFeatures.SyncToolSpecification(
        spec.tool(),
        (ctx, request) ->
            run(spec.tool(), request, null, hint, args -> spec.callHandler().apply(ctx, args)));
  }

  private McpSchema.CallToolResult run(
      McpSchema.Tool tool,
      McpSchema.CallToolRequest request,
      String conversationId,
      Optional<SideEffect> hint,
      Function<McpSchema.CallToolRequest, McpSchema.CallToolResult> delegate) {
    String correlationId = UUID.randomUUID().toString();
    try {
      Map<String, Object> arguments = request.arguments() == null ? Map.of() : request.arguments();
      String argsJson = json.writeValueAsString(arguments);
      var invocation =
          new ToolInvocation(
              principals.resolve(), tool.name(), argsJson, conversationId, correlationId);
      var holder = new McpSchema.CallToolResult[1];
      GuardResult result =
          guard.execute(
              invocation,
              hint,
              args -> {
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
        return replay(executed.result());
      }
      return McpSchema.CallToolResult.builder()
          .addTextContent(result.toModelText())
          .isError(true)
          .build();
    } catch (RuntimeException e) {
      log.error(
          "agentguard: guard unavailable for MCP tool '{}' correlationId={}",
          tool.name(),
          correlationId,
          e);
      return McpSchema.CallToolResult.builder()
          .addTextContent(
              new GuardResult.GuardUnavailable(tool.name(), correlationId).toModelText())
          .isError(true)
          .build();
    }
  }

  private McpSchema.CallToolResult replay(String stored) {
    try {
      return json.readValue(stored, McpSchema.CallToolResult.class);
    } catch (RuntimeException e) {
      return McpSchema.CallToolResult.builder().addTextContent(stored).isError(false).build();
    }
  }

  static String sessionId(McpSyncServerExchange exchange) {
    if (exchange == null) {
      return null;
    }
    try {
      return exchange.sessionId();
    } catch (RuntimeException e) {
      return null;
    }
  }

  static Optional<SideEffect> hint(McpSchema.Tool tool) {
    var a = tool.annotations();
    if (a != null && Boolean.TRUE.equals(a.readOnlyHint())) {
      return Optional.of(SideEffect.READ);
    }
    return Optional.empty();
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

  /**
   * Bean post-processing: wraps single specifications and lists of them; refuses async (WebFlux)
   * specifications, which are not guarded yet, rather than letting them run unguarded.
   */
  @SuppressWarnings("unchecked")
  Object guardBean(Object bean, String beanName) {
    if (bean instanceof McpServerFeatures.SyncToolSpecification s) {
      return guard(s);
    }
    if (bean instanceof McpStatelessServerFeatures.SyncToolSpecification s) {
      return guard(s);
    }
    if (isAsync(bean)) {
      throw new AgentGuardConfigurationException(
          "agentguard: bean '"
              + beanName
              + "' publishes async MCP tool specifications, which Agent Guard"
              + " does not guard yet. Use a sync (WebMVC / stateless) server or remove the bean.");
    }
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

  private static boolean isAsync(Object bean) {
    if (bean instanceof McpServerFeatures.AsyncToolSpecification
        || bean instanceof McpStatelessServerFeatures.AsyncToolSpecification) {
      return true;
    }
    return bean instanceof List<?> list
        && !list.isEmpty()
        && list.stream()
            .allMatch(
                e ->
                    e instanceof McpServerFeatures.AsyncToolSpecification
                        || e instanceof McpStatelessServerFeatures.AsyncToolSpecification);
  }
}

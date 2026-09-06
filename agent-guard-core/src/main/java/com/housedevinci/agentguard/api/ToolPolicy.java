package com.housedevinci.agentguard.api;

import com.housedevinci.agentguard.domain.SideEffect;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares the authorization policy of a tool method ({@code @Tool} or {@code @McpTool}).
 *
 * <p>Empty {@link #roles()}, {@link #scopes()} or {@link #tenants()} mean "no restriction on that
 * axis". {@link #sideEffect()} drives the approval gate: {@code WRITE} and {@code DESTRUCTIVE}
 * tools are parked for a human decision by default.
 *
 * <pre>{@code
 * @McpTool(name = "refund", description = "Refund an order")
 * @ToolPolicy(roles = "SUPPORT", sideEffect = SideEffect.WRITE)
 * public String refund(String orderId) { ... }
 * }</pre>
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface ToolPolicy {

  /** Roles allowed to call the tool (any-of). Empty = any role. */
  String[] roles() default {};

  /** OAuth2 scopes allowed to call the tool (any-of). Empty = any scope. */
  String[] scopes() default {};

  /** Tenants allowed to call the tool (any-of). Empty = any tenant. */
  String[] tenants() default {};

  /** What the tool does to the world; decides whether a human must approve. */
  SideEffect sideEffect() default SideEffect.READ;
}

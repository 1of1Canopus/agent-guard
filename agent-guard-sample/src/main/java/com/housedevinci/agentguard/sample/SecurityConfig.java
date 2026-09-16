package com.housedevinci.agentguard.sample;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Two users: the agent that calls tools, the approver who decides. HTTP Basic keeps it short.
 *
 * <p>#18: CSRF protects a session-carrying (cookie) client from a forged cross-site request. A
 * Basic-authenticated request with no session cannot be forged that way - there is no ambient
 * credential for a malicious page to replay, and no CSRF token endpoint this sample exposes for it
 * to fetch one from - so holding {@code /agentguard/**} to CSRF for that one shape of client only
 * ever returns a bare 401 it cannot comply with. That carve-out is scoped as narrowly as the sample
 * can make it: unsafe method, {@code /agentguard/**}, a session-less request, an {@code
 * Authorization: Basic} header. Anything else - including a browser session against these same
 * endpoints - is still held to the token, and a missing or invalid one comes back as a 403 that
 * names the reason instead of falling through to the generic handler.
 */
@Configuration
class SecurityConfig {

  private static final RequestMatcher AGENTGUARD =
      PathPatternRequestMatcher.pathPattern("/agentguard/**");

  private static boolean isUnsafeMethod(HttpServletRequest request) {
    var method = request.getMethod();
    return !(HttpMethod.GET.matches(method)
        || HttpMethod.HEAD.matches(method)
        || HttpMethod.TRACE.matches(method)
        || HttpMethod.OPTIONS.matches(method));
  }

  private static boolean isSessionlessBasicOnAgentGuard(HttpServletRequest request) {
    if (!AGENTGUARD.matches(request) || request.getSession(false) != null) {
      return false;
    }
    var authorization = request.getHeader("Authorization");
    return authorization != null
        && authorization.regionMatches(true, 0, "Basic ", 0, "Basic ".length());
  }

  /**
   * The default CSRF matcher restricted to unsafe methods, minus the session-less Basic carve-out
   * on {@code /agentguard/**} described above. Every other unsafe request, on this path or any
   * other, still needs a token.
   */
  private static boolean requiresCsrf(HttpServletRequest request) {
    return isUnsafeMethod(request) && !isSessionlessBasicOnAgentGuard(request);
  }

  private static AccessDeniedHandler namingMissingCsrfToken() {
    var fallback = new AccessDeniedHandlerImpl();
    return (request, response, ex) -> {
      if (ex instanceof CsrfException) {
        response.setStatus(403);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"CSRF token missing or invalid\"}");
        return;
      }
      fallback.handle(request, response, ex);
    };
  }

  @Bean
  SecurityFilterChain security(HttpSecurity http) throws Exception {
    return http.csrf(
            csrf ->
                csrf.ignoringRequestMatchers("/mcp/**") // the MCP transport is never session-based
                    .requireCsrfProtectionMatcher(SecurityConfig::requiresCsrf))
        .exceptionHandling(e -> e.accessDeniedHandler(namingMissingCsrfToken()))
        .authorizeHttpRequests(
            a ->
                a.requestMatchers("/agentguard/**")
                    .hasRole("APPROVER")
                    .anyRequest()
                    .authenticated())
        .httpBasic(Customizer.withDefaults())
        .build();
  }

  @Bean
  InMemoryUserDetailsManager users() {
    return new InMemoryUserDetailsManager(
        User.withUsername("agent").password("{noop}agent").roles("AGENT").build(),
        User.withUsername("alice").password("{noop}alice").roles("APPROVER").build());
  }
}

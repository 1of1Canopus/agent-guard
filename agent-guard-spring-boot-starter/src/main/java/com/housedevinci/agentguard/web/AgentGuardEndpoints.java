package com.housedevinci.agentguard.web;

import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.domain.AgentGuardException;
import com.housedevinci.agentguard.domain.ApprovalHashMismatchException;
import com.housedevinci.agentguard.domain.ArgumentRedactor;
import com.housedevinci.agentguard.domain.AuditEvent;
import com.housedevinci.agentguard.domain.AuditReader;
import com.housedevinci.agentguard.domain.DecisionId;
import com.housedevinci.agentguard.domain.DecisionNotFoundException;
import com.housedevinci.agentguard.domain.IllegalDecisionTransitionException;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.SelfApprovalException;
import com.housedevinci.agentguard.security.PrincipalResolver;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Approval inbox and audit query, JSON over HTTP, under {@code agentguard.endpoints.base-path} when
 * {@code agentguard.endpoints.enabled=true}. The approver is the authenticated principal; anonymous
 * callers are refused (401) unless {@code agentguard.endpoints.allow-anonymous=true}. An approver
 * with a tenant only sees and decides that tenant's decisions (another tenant's decision is a 404).
 * Approving requires the {@code argsHash} the approver reviewed (fetch the full redacted arguments
 * from {@code GET /decisions/{id}/arguments}); a mismatch is a 409 and nothing runs; the principal
 * that parked a call may not decide it (403).
 */
@Controller
@ResponseBody
@RequestMapping("${agentguard.endpoints.base-path:/agentguard}")
public class AgentGuardEndpoints {

  private final ApprovalService approvals;
  private final AuditReader audit;
  private final PrincipalResolver principals;
  private final ArgumentRedactor redactor;
  private final boolean allowAnonymous;
  private final boolean tenantScoped;
  private final boolean requireTenant;

  public AgentGuardEndpoints(
      ApprovalService approvals,
      AuditReader audit,
      PrincipalResolver principals,
      ArgumentRedactor redactor,
      boolean allowAnonymous) {
    this(approvals, audit, principals, redactor, allowAnonymous, true);
  }

  public AgentGuardEndpoints(
      ApprovalService approvals,
      AuditReader audit,
      PrincipalResolver principals,
      ArgumentRedactor redactor,
      boolean allowAnonymous,
      boolean tenantScoped) {
    this(approvals, audit, principals, redactor, allowAnonymous, tenantScoped, true);
  }

  /**
   * @param requireTenant when {@code tenantScoped}, refuse (403) an approver with no tenant instead
   *     of letting them see and decide every tenant's work (Cipher C9)
   */
  public AgentGuardEndpoints(
      ApprovalService approvals,
      AuditReader audit,
      PrincipalResolver principals,
      ArgumentRedactor redactor,
      boolean allowAnonymous,
      boolean tenantScoped,
      boolean requireTenant) {
    this.approvals = approvals;
    this.audit = audit;
    this.principals = principals;
    this.redactor = redactor;
    this.allowAnonymous = allowAnonymous;
    this.tenantScoped = tenantScoped;
    this.requireTenant = requireTenant;
  }

  @GetMapping("/decisions")
  public List<DecisionResponse> pending(
      @RequestParam(defaultValue = "100") int limit, Principal caller) {
    approver(caller);
    var tenant = approverTenant();
    return approvals.pending(Math.max(1, Math.min(limit, 500)), tenant.orElse(null)).stream()
        .map(DecisionResponse::from)
        .toList();
  }

  @GetMapping("/decisions/{id}")
  public DecisionResponse get(@PathVariable String id, Principal caller) {
    approver(caller);
    return DecisionResponse.from(load(id));
  }

  /** The complete, redacted arguments: what the approver reads before attesting the hash. */
  @GetMapping("/decisions/{id}/arguments")
  public Map<String, String> arguments(@PathVariable String id, Principal caller) {
    approver(caller);
    var d = load(id);
    return Map.of(
        "id", d.id().toString(),
        "argsHash", d.argsHash(),
        "arguments", redactor.redact(d.argumentsJson()));
  }

  @PostMapping("/decisions/{id}/approve")
  public Map<String, Object> approve(
      @PathVariable String id, @RequestParam String argsHash, Principal caller) {
    String approver = approver(caller);
    var outcome = approvals.approve(load(id).id(), approver, argsHash);
    return Map.of(
        "decision", DecisionResponse.from(outcome.decision()),
        "result", outcome.result().toModelText(),
        "error", outcome.result().isError());
  }

  @PostMapping("/decisions/{id}/reject")
  public DecisionResponse reject(@PathVariable String id, Principal caller) {
    String approver = approver(caller);
    return DecisionResponse.from(approvals.reject(load(id).id(), approver));
  }

  @GetMapping("/audit")
  public List<AuditEvent> audit(@RequestParam(defaultValue = "100") int limit, Principal caller) {
    approver(caller);
    var tenant = approverTenant();
    return audit.latest(tenant.orElse(null), Math.max(1, Math.min(limit, 500)));
  }

  /** A decision of another tenant does not exist for this approver (404, not 403). */
  private PendingDecision load(String id) {
    var decisionId = DecisionId.of(id);
    var tenant = approverTenant();
    return approvals
        .find(decisionId)
        .filter(d -> visible(d, tenant))
        .orElseThrow(() -> new DecisionNotFoundException(decisionId));
  }

  /**
   * C9: tenant scoping must not fail open. When {@code tenantScoped}, an approver whose resolver
   * yields no tenant (a missing claim, a service account, a misconfigured {@code TenantResolver})
   * is refused instead of silently seeing and deciding every tenant's work, unless the deployment
   * has explicitly opted into a cross-tenant approver ({@code require-tenant=false}).
   */
  private Optional<String> approverTenant() {
    if (!tenantScoped) {
      return Optional.empty();
    }
    var tenant = principals.resolve().tenantId();
    if (tenant.isEmpty() && requireTenant) {
      throw new MissingTenantException();
    }
    return tenant;
  }

  private static boolean visible(PendingDecision d, Optional<String> tenant) {
    return tenant.isEmpty() || tenant.equals(d.principal().tenantId());
  }

  /** The approver: the resolved security principal, else the servlet principal; never anonymous. */
  private String approver(Principal p) {
    var resolved = principals.resolve();
    String anonymous = com.housedevinci.agentguard.domain.Principal.ANONYMOUS_ID;
    String name =
        anonymous.equals(resolved.id())
            ? (p == null || p.getName() == null ? anonymous : p.getName())
            : resolved.id();
    if (anonymous.equals(name) && !allowAnonymous) {
      throw new AnonymousApproverException();
    }
    return name;
  }

  static final class AnonymousApproverException extends RuntimeException {
    AnonymousApproverException() {
      super(
          "anonymous approver refused; authenticate, or set"
              + " agentguard.endpoints.allow-anonymous=true (trial only)");
    }
  }

  @ExceptionHandler(AnonymousApproverException.class)
  ResponseEntity<Map<String, String>> unauthorized(AnonymousApproverException e) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body(Map.of("code", "AG-HTTP-401", "message", e.getMessage()));
  }

  static final class MissingTenantException extends RuntimeException {
    MissingTenantException() {
      super(
          "approver has no tenant; refused under agentguard.endpoints.tenant-scoped=true and"
              + " require-tenant=true. Set agentguard.endpoints.require-tenant=false only for a"
              + " deliberate cross-tenant approver role.");
    }
  }

  @ExceptionHandler(MissingTenantException.class)
  ResponseEntity<Map<String, String>> missingTenant(MissingTenantException e) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(Map.of("code", "AG-HTTP-403", "message", e.getMessage()));
  }

  @ExceptionHandler(SelfApprovalException.class)
  ResponseEntity<Map<String, String>> forbidden(SelfApprovalException e) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(Map.of("code", e.code(), "message", e.getMessage()));
  }

  @ExceptionHandler(DecisionNotFoundException.class)
  ResponseEntity<Map<String, String>> notFound(DecisionNotFoundException e) {
    return ResponseEntity.status(HttpStatus.NOT_FOUND)
        .body(Map.of("code", e.code(), "message", e.getMessage()));
  }

  @ExceptionHandler({IllegalDecisionTransitionException.class, ApprovalHashMismatchException.class})
  ResponseEntity<Map<String, String>> conflict(AgentGuardException e) {
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("code", e.code(), "message", e.getMessage()));
  }

  @ExceptionHandler(AgentGuardException.class)
  ResponseEntity<Map<String, String>> other(AgentGuardException e) {
    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_CONTENT)
        .body(Map.of("code", e.code(), "message", e.getMessage()));
  }

  @ExceptionHandler(IllegalArgumentException.class)
  ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
    return ResponseEntity.badRequest()
        .body(Map.of("code", "AG-HTTP-400", "message", "invalid request"));
  }
}

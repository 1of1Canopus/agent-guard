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
import com.housedevinci.agentguard.security.PrincipalResolver;
import java.security.Principal;
import java.util.List;
import java.util.Map;
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
 * callers are refused (401) unless {@code agentguard.endpoints.allow-anonymous=true}. Approving
 * requires the {@code argsHash} the approver reviewed (fetch the full redacted arguments from
 * {@code GET /decisions/{id}/arguments}); a mismatch is a 409 and nothing runs.
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

  public AgentGuardEndpoints(
      ApprovalService approvals,
      AuditReader audit,
      PrincipalResolver principals,
      ArgumentRedactor redactor,
      boolean allowAnonymous) {
    this.approvals = approvals;
    this.audit = audit;
    this.principals = principals;
    this.redactor = redactor;
    this.allowAnonymous = allowAnonymous;
  }

  @GetMapping("/decisions")
  public List<DecisionResponse> pending(
      @RequestParam(defaultValue = "100") int limit, Principal caller) {
    approver(caller);
    return approvals.pending(Math.max(1, Math.min(limit, 500))).stream()
        .map(DecisionResponse::from)
        .toList();
  }

  @GetMapping("/decisions/{id}")
  public DecisionResponse get(@PathVariable String id, Principal caller) {
    approver(caller);
    var decisionId = DecisionId.of(id);
    return approvals
        .find(decisionId)
        .map(DecisionResponse::from)
        .orElseThrow(() -> new DecisionNotFoundException(decisionId));
  }

  /** The complete, redacted arguments: what the approver reads before attesting the hash. */
  @GetMapping("/decisions/{id}/arguments")
  public Map<String, String> arguments(@PathVariable String id, Principal caller) {
    approver(caller);
    var decisionId = DecisionId.of(id);
    var d = approvals.find(decisionId).orElseThrow(() -> new DecisionNotFoundException(decisionId));
    return Map.of(
        "id",
        d.id().toString(),
        "argsHash",
        d.argsHash(),
        "arguments",
        redactor.redact(d.argumentsJson()));
  }

  @PostMapping("/decisions/{id}/approve")
  public Map<String, Object> approve(
      @PathVariable String id, @RequestParam String argsHash, Principal caller) {
    var outcome = approvals.approve(DecisionId.of(id), approver(caller), argsHash);
    return Map.of(
        "decision", DecisionResponse.from(outcome.decision()),
        "result", outcome.result().toModelText(),
        "error", outcome.result().isError());
  }

  @PostMapping("/decisions/{id}/reject")
  public DecisionResponse reject(@PathVariable String id, Principal caller) {
    return DecisionResponse.from(approvals.reject(DecisionId.of(id), approver(caller)));
  }

  @GetMapping("/audit")
  public List<AuditEvent> audit(@RequestParam(defaultValue = "100") int limit, Principal caller) {
    approver(caller);
    return audit.latest(Math.max(1, Math.min(limit, 500)));
  }

  /** The approver: the resolved security principal, else the servlet principal; never anonymous. */
  private String approver(Principal p) {
    var resolved = principals.resolve();
    String name =
        com.housedevinci.agentguard.domain.Principal.ANONYMOUS_ID.equals(resolved.id())
            ? (p == null || p.getName() == null
                ? com.housedevinci.agentguard.domain.Principal.ANONYMOUS_ID
                : p.getName())
            : resolved.id();
    if (com.housedevinci.agentguard.domain.Principal.ANONYMOUS_ID.equals(name) && !allowAnonymous) {
      throw new AnonymousApproverException();
    }
    return name;
  }

  static final class AnonymousApproverException extends RuntimeException {
    AnonymousApproverException() {
      super(
          "anonymous approver refused; authenticate, or set agentguard.endpoints.allow-anonymous=true (trial only)");
    }
  }

  @ExceptionHandler(AnonymousApproverException.class)
  ResponseEntity<Map<String, String>> unauthorized(AnonymousApproverException e) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body(Map.of("code", "AG-HTTP-401", "message", e.getMessage()));
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

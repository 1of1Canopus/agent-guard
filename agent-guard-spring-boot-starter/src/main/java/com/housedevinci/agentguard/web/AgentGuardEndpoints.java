package com.housedevinci.agentguard.web;

import com.housedevinci.agentguard.application.ApprovalService;
import com.housedevinci.agentguard.domain.AgentGuardException;
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
 * Approval inbox and audit query, JSON over HTTP. Registered under {@code
 * agentguard.endpoints.base-path} when {@code agentguard.endpoints.enabled=true}. Protect it with
 * Spring Security: the approver name is taken from the authenticated request principal.
 */
@Controller
@ResponseBody
@RequestMapping("${agentguard.endpoints.base-path:/agentguard}")
public class AgentGuardEndpoints {

  private final ApprovalService approvals;
  private final AuditReader audit;
  private final PrincipalResolver principals;

  public AgentGuardEndpoints(
      ApprovalService approvals, AuditReader audit, PrincipalResolver principals) {
    this.approvals = approvals;
    this.audit = audit;
    this.principals = principals;
  }

  @GetMapping("/decisions")
  public List<DecisionResponse> pending(@RequestParam(defaultValue = "100") int limit) {
    return approvals.pending(Math.max(1, Math.min(limit, 500))).stream()
        .map(DecisionResponse::from)
        .toList();
  }

  @GetMapping("/decisions/{id}")
  public DecisionResponse get(@PathVariable String id) {
    var decisionId = DecisionId.of(id);
    return approvals
        .find(decisionId)
        .map(DecisionResponse::from)
        .orElseThrow(() -> new DecisionNotFoundException(decisionId));
  }

  @PostMapping("/decisions/{id}/approve")
  public Map<String, Object> approve(@PathVariable String id, Principal approver) {
    var outcome = approvals.approve(DecisionId.of(id), name(approver));
    return Map.of(
        "decision",
        DecisionResponse.from(outcome.decision()),
        "result",
        outcome.result().toModelText(),
        "error",
        outcome.result().isError());
  }

  @PostMapping("/decisions/{id}/reject")
  public DecisionResponse reject(@PathVariable String id, Principal approver) {
    return DecisionResponse.from(approvals.reject(DecisionId.of(id), name(approver)));
  }

  @GetMapping("/audit")
  public List<AuditEvent> audit(@RequestParam(defaultValue = "100") int limit) {
    return audit.latest(Math.max(1, Math.min(limit, 500)));
  }

  /** The approver: the resolved security principal, else the servlet principal, else anonymous. */
  private String name(Principal p) {
    var resolved = principals.resolve();
    if (!com.housedevinci.agentguard.domain.Principal.ANONYMOUS_ID.equals(resolved.id())) {
      return resolved.id();
    }
    return p == null || p.getName() == null
        ? com.housedevinci.agentguard.domain.Principal.ANONYMOUS_ID
        : p.getName();
  }

  @ExceptionHandler(DecisionNotFoundException.class)
  ResponseEntity<Map<String, String>> notFound(DecisionNotFoundException e) {
    return ResponseEntity.status(HttpStatus.NOT_FOUND)
        .body(Map.of("code", e.code(), "message", e.getMessage()));
  }

  @ExceptionHandler(IllegalDecisionTransitionException.class)
  ResponseEntity<Map<String, String>> conflict(IllegalDecisionTransitionException e) {
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

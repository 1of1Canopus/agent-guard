package com.housedevinci.agentguard.adapter.notify;

import com.housedevinci.agentguard.application.Json;
import com.housedevinci.agentguard.domain.Notifier;
import com.housedevinci.agentguard.domain.PendingDecision;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * POSTs a JSON description of the parked call to a URL (Slack-compatible receivers, n8n, your own
 * inbox). Never throws: a failed delivery is logged and the call stays parked.
 */
public final class WebhookNotifier implements Notifier {

  private static final Logger log = LoggerFactory.getLogger(WebhookNotifier.class);

  private final HttpClient client;
  private final URI url;
  private final String secretHeader;
  private final Duration timeout;

  public WebhookNotifier(URI url, String secretHeader, Duration timeout) {
    this(HttpClient.newBuilder().connectTimeout(timeout).build(), url, secretHeader, timeout);
  }

  WebhookNotifier(HttpClient client, URI url, String secretHeader, Duration timeout) {
    this.client = Objects.requireNonNull(client, "client");
    this.url = Objects.requireNonNull(url, "url");
    this.secretHeader = secretHeader;
    this.timeout = Objects.requireNonNull(timeout, "timeout");
  }

  public static String payload(PendingDecision d) {
    return Json.object()
        .put("event", "agentguard.approval.requested")
        .put("decisionId", d.id().toString())
        .put("tool", d.tool().name())
        .put("sideEffect", d.tool().sideEffect().name())
        .put("principal", d.principal().id())
        .put("tenant", d.principal().tenantId().orElse(null))
        .put("argsPreview", d.argsPreview())
        .put("argsHash", d.argsHash())
        .put("createdAt", d.createdAt().toString())
        .put("expiresAt", d.expiresAt().toString())
        .put(
            "text",
            "Agent Guard: '"
                + d.tool().name()
                + "' by "
                + d.principal().id()
                + " needs approval (decision "
                + d.id()
                + ")")
        .toString();
  }

  @Override
  public void notify(PendingDecision d) {
    var builder =
        HttpRequest.newBuilder(url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload(d)));
    if (secretHeader != null && !secretHeader.isBlank()) {
      builder.header("X-AgentGuard-Token", secretHeader);
    }
    try {
      HttpResponse<Void> response =
          client.send(builder.build(), HttpResponse.BodyHandlers.discarding());
      if (response.statusCode() >= 300) {
        log.warn(
            "Approval webhook {} answered {} for decision {}",
            url.getHost(),
            response.statusCode(),
            d.id());
      }
    } catch (java.io.IOException e) {
      log.warn(
          "Approval webhook {} failed for decision {}: {}", url.getHost(), d.id(), e.toString());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      log.warn("Approval webhook interrupted for decision {}", d.id());
    }
  }
}

package com.housedevinci.agentguard.adapter.notify;

import com.housedevinci.agentguard.application.Json;
import com.housedevinci.agentguard.domain.Notifier;
import com.housedevinci.agentguard.domain.PendingDecision;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * POSTs a JSON description of the parked call to a URL (Slack-compatible receivers, n8n, your own
 * inbox). Never throws for delivery failures: they are logged and the call stays parked.
 *
 * <p>Transport: the URL must be {@code https} unless the host is loopback or {@code allowInsecure}
 * is set (checked at construction, so at startup). Authenticity: with a secret, every request
 * carries {@code X-AgentGuard-Timestamp} (epoch seconds) and {@code X-AgentGuard-Signature:
 * v1=hex(HMAC-SHA256(secret, timestamp + "." + body))}; receivers recompute and reject stale
 * timestamps. The static {@code X-AgentGuard-Token} header is only sent with {@code legacyToken}.
 */
public final class WebhookNotifier implements Notifier {

  private static final Logger log = LoggerFactory.getLogger(WebhookNotifier.class);
  private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "::1", "[::1]");

  private final HttpClient client;
  private final URI url;
  private final String secret;
  private final Duration timeout;
  private final boolean legacyToken;
  private final Clock clock;

  public WebhookNotifier(URI url, String secret, Duration timeout) {
    this(url, secret, timeout, false, false);
  }

  public WebhookNotifier(
      URI url, String secret, Duration timeout, boolean allowInsecure, boolean legacyToken) {
    this(
        HttpClient.newBuilder().connectTimeout(timeout).build(),
        url,
        secret,
        timeout,
        allowInsecure,
        legacyToken,
        Clock.systemUTC());
  }

  WebhookNotifier(
      HttpClient client,
      URI url,
      String secret,
      Duration timeout,
      boolean allowInsecure,
      boolean legacyToken,
      Clock clock) {
    this.client = Objects.requireNonNull(client, "client");
    this.url = Objects.requireNonNull(url, "url");
    this.secret = secret == null || secret.isBlank() ? null : secret;
    this.timeout = Objects.requireNonNull(timeout, "timeout");
    this.legacyToken = legacyToken;
    this.clock = clock;
    if (!isSecure(url) && !allowInsecure) {
      throw new IllegalArgumentException(
          "agentguard.approval.notifier.webhook-url must use https (or a loopback host); set"
              + " agentguard.approval.notifier.webhook-allow-insecure=true for a local trial");
    }
  }

  static boolean isSecure(URI url) {
    String scheme = url.getScheme() == null ? "" : url.getScheme().toLowerCase(Locale.ROOT);
    String host = url.getHost() == null ? "" : url.getHost().toLowerCase(Locale.ROOT);
    return "https".equals(scheme) || LOOPBACK.contains(host);
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

  /** {@code v1=hex(HMAC-SHA256(secret, timestamp + "." + body))}; what a receiver recomputes. */
  public static String signature(String secret, long timestamp, String body) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      byte[] sig = mac.doFinal((timestamp + "." + body).getBytes(StandardCharsets.UTF_8));
      return "v1=" + HexFormat.of().formatHex(sig);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 not available", e);
    }
  }

  @Override
  public void notify(PendingDecision d) {
    String body = payload(d);
    var builder =
        HttpRequest.newBuilder(url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body));
    if (secret != null) {
      long ts = clock.instant().getEpochSecond();
      builder.header("X-AgentGuard-Timestamp", Long.toString(ts));
      builder.header("X-AgentGuard-Signature", signature(secret, ts, body));
      if (legacyToken) {
        builder.header("X-AgentGuard-Token", secret);
      }
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

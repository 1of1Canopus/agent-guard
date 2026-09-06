package com.housedevinci.agentguard.adapter.notify;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolRef;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class NotifiersTest {

  static WireMockServer wiremock;

  @BeforeAll
  static void start() {
    wiremock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wiremock.start();
  }

  @AfterAll
  static void stop() {
    wiremock.stop();
  }

  private static PendingDecision decision() {
    var now = Instant.parse("2026-09-06T10:00:00Z");
    return PendingDecision.park(
        new Principal("bob", Set.of("AGENT"), Set.of(), "acme"),
        new ToolRef("refund", SideEffect.WRITE),
        "{\"amount\":5,\"password\":\"x\"}",
        "{\"amount\":5,\"password\":\"***\"}",
        null,
        "corr-1",
        now,
        now.plus(Duration.ofHours(1)));
  }

  private static URI hook() {
    return URI.create("http://127.0.0.1:" + wiremock.port() + "/hook");
  }

  @Test
  void webhook_posts_signed_json_payload() {
    wiremock.stubFor(post(urlEqualTo("/hook")).willReturn(aResponse().withStatus(204)));
    var clock = Clock.fixed(Instant.parse("2026-09-06T12:00:00Z"), ZoneOffset.UTC);
    new WebhookNotifier(
            java.net.http.HttpClient.newHttpClient(),
            hook(),
            "s3cret",
            Duration.ofSeconds(2),
            false,
            false,
            clock)
        .notify(decision());
    var requests = wiremock.findAll(postRequestedFor(urlEqualTo("/hook")));
    assertThat(requests).hasSize(1);
    var req = requests.get(0);
    String body = req.getBodyAsString();
    assertThat(body)
        .contains("\"event\":\"agentguard.approval.requested\"")
        .contains("\"tool\":\"refund\"")
        .contains("\\\"password\\\":\\\"***\\\"")
        .doesNotContain("\\\"x\\\"");
    long ts = Instant.parse("2026-09-06T12:00:00Z").getEpochSecond();
    assertThat(req.getHeader("X-AgentGuard-Timestamp")).isEqualTo(Long.toString(ts));
    // what a receiver recomputes
    assertThat(req.getHeader("X-AgentGuard-Signature"))
        .isEqualTo(WebhookNotifier.signature("s3cret", ts, body));
    assertThat(req.getHeader("X-AgentGuard-Signature")).startsWith("v1=").hasSize(3 + 64);
    assertThat(req.containsHeader("X-AgentGuard-Token")).isFalse();
    assertThat(WebhookNotifier.signature("s3cret", ts, body))
        .isNotEqualTo(WebhookNotifier.signature("other", ts, body));
  }

  @Test
  void legacy_token_only_when_asked_and_no_headers_without_a_secret() {
    wiremock.resetRequests();
    wiremock.stubFor(post(urlEqualTo("/hook")).willReturn(aResponse().withStatus(200)));
    new WebhookNotifier(hook(), "s3cret", Duration.ofSeconds(2), false, true).notify(decision());
    new WebhookNotifier(hook(), null, Duration.ofSeconds(2), false, false).notify(decision());
    var requests = wiremock.findAll(postRequestedFor(urlEqualTo("/hook")));
    assertThat(requests.get(0).getHeader("X-AgentGuard-Token")).isEqualTo("s3cret");
    assertThat(requests.get(1).containsHeader("X-AgentGuard-Signature")).isFalse();
    assertThat(requests.get(1).containsHeader("X-AgentGuard-Token")).isFalse();
  }

  @Test
  void non_https_urls_are_refused_at_construction_unless_loopback_or_allowed() {
    assertThatThrownBy(
            () ->
                new WebhookNotifier(
                    URI.create("http://hooks.example.com/x"), "s", Duration.ofSeconds(1)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("agentguard.approval.notifier.webhook-url")
        .hasMessageContaining("webhook-allow-insecure");
    assertThatCode(
            () ->
                new WebhookNotifier(
                    URI.create("http://hooks.example.com/x"),
                    "s",
                    Duration.ofSeconds(1),
                    true,
                    false))
        .doesNotThrowAnyException();
    assertThatCode(
            () ->
                new WebhookNotifier(
                    URI.create("https://hooks.example.com/x"), "s", Duration.ofSeconds(1)))
        .doesNotThrowAnyException();
    assertThatCode(
            () ->
                new WebhookNotifier(URI.create("http://localhost:9/x"), "s", Duration.ofSeconds(1)))
        .doesNotThrowAnyException();
  }

  @Test
  void webhook_never_throws_when_receiver_is_down_or_errors() {
    var notifier =
        new WebhookNotifier(URI.create("http://127.0.0.1:1/hook"), null, Duration.ofMillis(500));
    assertThatCode(() -> notifier.notify(decision())).doesNotThrowAnyException();
    wiremock.stubFor(post(urlEqualTo("/err")).willReturn(aResponse().withStatus(500)));
    assertThatCode(
            () ->
                new WebhookNotifier(
                        URI.create("http://127.0.0.1:" + wiremock.port() + "/err"),
                        "",
                        Duration.ofSeconds(2))
                    .notify(decision()))
        .doesNotThrowAnyException();
  }

  @Test
  void logging_and_composite_swallow_failures() {
    var composite =
        new CompositeNotifier(
            List.of(
                d -> {
                  throw new IllegalStateException("boom");
                },
                new LoggingNotifier()));
    assertThatCode(() -> composite.notify(decision())).doesNotThrowAnyException();
  }
}

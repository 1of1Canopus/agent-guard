package com.housedevinci.agentguard.adapter.notify;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.housedevinci.agentguard.domain.PendingDecision;
import com.housedevinci.agentguard.domain.Principal;
import com.housedevinci.agentguard.domain.SideEffect;
import com.housedevinci.agentguard.domain.ToolRef;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class NotifiersTest {

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

  @Test
  void webhook_posts_json_payload_with_secret_header() throws IOException {
    var body = new AtomicReference<String>();
    var token = new AtomicReference<String>();
    var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/hook", ex -> {
      body.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      token.set(ex.getRequestHeaders().getFirst("X-AgentGuard-Token"));
      ex.sendResponseHeaders(204, -1);
      ex.close();
    });
    server.start();
    try {
      var url = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/hook");
      new WebhookNotifier(url, "s3cret", Duration.ofSeconds(2)).notify(decision());
      assertThat(body.get()).contains("\"event\":\"agentguard.approval.requested\"").contains("\"tool\":\"refund\"")
          .contains("\\\"password\\\":\\\"***\\\"").doesNotContain("hunter").doesNotContain("\\\"x\\\"");
      assertThat(token.get()).isEqualTo("s3cret");
    } finally {
      server.stop(0);
    }
  }

  @Test
  void webhook_never_throws_when_receiver_is_down_or_errors() throws IOException {
    var notifier = new WebhookNotifier(URI.create("http://127.0.0.1:1/hook"), null, Duration.ofMillis(500));
    assertThatCode(() -> notifier.notify(decision())).doesNotThrowAnyException();

    var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/hook", ex -> {
      ex.sendResponseHeaders(500, -1);
      ex.close();
    });
    server.start();
    try {
      var url = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/hook");
      assertThatCode(() -> new WebhookNotifier(url, "", Duration.ofSeconds(2)).notify(decision())).doesNotThrowAnyException();
    } finally {
      server.stop(0);
    }
  }

  @Test
  void logging_and_composite_swallow_failures() {
    var composite = new CompositeNotifier(List.of(d -> {
      throw new IllegalStateException("boom");
    }, new LoggingNotifier()));
    assertThatCode(() -> composite.notify(decision())).doesNotThrowAnyException();
  }
}

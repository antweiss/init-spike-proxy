package com.initspike.proxy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/** Admin surface for runtime operations. Currently: POST /admin/reload to swap the rule set. */
final class AdminHandler implements HttpHandler {
  private final AtomicReference<RuleEngine> engineRef;
  private final ProxyConfig defaults;

  AdminHandler(AtomicReference<RuleEngine> engineRef, ProxyConfig defaults) {
    this.engineRef = engineRef;
    this.defaults = defaults;
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    String path = exchange.getRequestURI().getPath();
    if (!"/admin/reload".equals(path)) {
      sendPlain(exchange, 404, "unknown admin endpoint: " + path);
      return;
    }
    if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
      sendPlain(exchange, 405, "use POST");
      return;
    }

    int ruleCount = defaults.ruleCount;
    int payloadBytes = defaults.payloadBytes;
    try {
      String query = exchange.getRequestURI().getRawQuery();
      if (query != null) {
        for (String part : query.split("&")) {
          int eq = part.indexOf('=');
          if (eq <= 0) continue;
          String key = part.substring(0, eq);
          String value = part.substring(eq + 1);
          switch (key) {
            case "count" -> ruleCount = Integer.parseInt(value);
            case "payload" -> payloadBytes = Integer.parseInt(value);
            default -> {}
          }
        }
      }
    } catch (NumberFormatException e) {
      sendPlain(exchange, 400, "bad numeric parameter: " + e.getMessage());
      return;
    }

    if (ruleCount < 0 || payloadBytes < 0) {
      sendPlain(exchange, 400, "count and payload must be non-negative");
      return;
    }

    long started = System.nanoTime();
    RuleEngine next = InitSpike.loadRules(ruleCount, payloadBytes);
    engineRef.set(next);
    long elapsedMs = (System.nanoTime() - started) / 1_000_000L;

    sendPlain(
        exchange,
        200,
        "reloaded rules=" + next.size() + " indexes=" + next.indexSize() + " elapsed=" + elapsedMs + "ms");
  }

  private static void sendPlain(HttpExchange exchange, int status, String message) throws IOException {
    byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().put("Content-Type", List.of("text/plain; charset=utf-8"));
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }
}

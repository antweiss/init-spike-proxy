package com.initspike.proxy;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

final class HttpProxyHandler implements HttpHandler {
  private static final Set<String> HOP_BY_HOP =
      Set.of(
          "connection",
          "keep-alive",
          "proxy-authenticate",
          "proxy-authorization",
          "te",
          "trailers",
          "transfer-encoding",
          "upgrade",
          "host");

  private final AtomicReference<RuleEngine> engineRef;
  private final HttpClient client;

  HttpProxyHandler(AtomicReference<RuleEngine> engineRef) {
    this.engineRef = engineRef;
    this.client =
        HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build();
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    try {
      dispatch(exchange);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      sendPlain(exchange, 502, "upstream interrupted");
    } catch (Exception e) {
      String detail = e.getClass().getSimpleName();
      if (e.getMessage() != null && !e.getMessage().isBlank()) {
        detail += ": " + e.getMessage();
      }
      if (e.getCause() != null) {
        detail += " (" + e.getCause().getClass().getSimpleName() + ")";
      }
      sendPlain(exchange, 502, "proxy error: " + detail);
    }
  }

  private void dispatch(HttpExchange exchange) throws IOException, InterruptedException {
    RuleEngine engine = engineRef.get();
    String path = exchange.getRequestURI().getPath();
    if ("/healthz".equals(path) || "/readyz".equals(path)) {
      sendPlain(exchange, 200, "ok rules=" + engine.size());
      return;
    }

    URI target = resolveTarget(exchange);
    if (target == null) {
      sendPlain(
          exchange,
          400,
          "usage: GET /proxy?url=https://example.com  or send a proxy request with an absolute URI");
      return;
    }

    AccessRule rule = engine.match(target);
    if (rule.action == AccessRule.RuleAction.DENY) {
      sendPlain(exchange, 403, "denied by rule " + rule.id);
      return;
    }

    URI upstream = target;
    if (rule.action == AccessRule.RuleAction.REWRITE && !rule.rewriteTarget.isBlank()) {
      upstream = URI.create(rule.rewriteTarget);
    }

    byte[] body = exchange.getRequestBody().readAllBytes();
    HttpRequest.Builder req =
        HttpRequest.newBuilder(upstream)
            .timeout(Duration.ofSeconds(30))
            .method(
                exchange.getRequestMethod(),
                body.length == 0
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofByteArray(body));

    copyRequestHeaders(exchange.getRequestHeaders(), req);
    req.header("X-Proxy-Rule-Id", String.valueOf(rule.id));

    HttpResponse<byte[]> response = client.send(req.build(), HttpResponse.BodyHandlers.ofByteArray());
    Headers out = exchange.getResponseHeaders();
    response
        .headers()
        .map()
        .forEach(
            (name, values) -> {
              if (!HOP_BY_HOP.contains(name.toLowerCase())) {
                out.put(name, values);
              }
            });
    out.add("X-Proxy-Rule-Id", String.valueOf(rule.id));
    out.add("X-Proxy-Rule-Action", rule.action.name());

    byte[] respBody = response.body() == null ? new byte[0] : response.body();
    exchange.sendResponseHeaders(response.statusCode(), respBody.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(respBody);
    }
  }

  private static URI resolveTarget(HttpExchange exchange) {
    URI requestUri = exchange.getRequestURI();
    if (requestUri.isAbsolute() && requestUri.getScheme() != null) {
      return requestUri;
    }
    String query = requestUri.getRawQuery();
    if (query != null) {
      for (String part : query.split("&")) {
        int eq = part.indexOf('=');
        if (eq > 0 && "url".equals(part.substring(0, eq))) {
          return URI.create(java.net.URLDecoder.decode(part.substring(eq + 1), java.nio.charset.StandardCharsets.UTF_8));
        }
      }
    }
    String dest = exchange.getRequestHeaders().getFirst("X-Destination");
    if (dest != null && !dest.isBlank()) {
      return URI.create(dest);
    }
    return null;
  }

  private static void copyRequestHeaders(Headers in, HttpRequest.Builder req) {
    in.forEach(
        (name, values) -> {
          if (HOP_BY_HOP.contains(name.toLowerCase())) {
            return;
          }
          for (String value : values) {
            try {
              req.header(name, value);
            } catch (IllegalArgumentException ignored) {
              // Restricted hop-by-hop or invalid header names from the client.
            }
          }
        });
  }

  private static void sendPlain(HttpExchange exchange, int status, String message) throws IOException {
    byte[] bytes = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    exchange.getResponseHeaders().put("Content-Type", List.of("text/plain; charset=utf-8"));
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }
}

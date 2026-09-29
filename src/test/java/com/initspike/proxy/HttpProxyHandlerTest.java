package com.initspike.proxy;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration-style tests for HttpProxyHandler using a real embedded HttpServer.
 * Port 0 is used so the OS picks a free port automatically.
 */
class HttpProxyHandlerTest {

    private HttpServer server;
    private HttpClient client;
    private int port;
    private RuleEngine engine;

    /** Build a minimal RuleEngine with one DENY rule for blocked.internal */
    private static RuleEngine buildEngine() {
        AccessRule denyRule = new AccessRule(
                1,
                "blocked.internal",
                "/",
                Pattern.compile("^https?://blocked\\.internal(/.*)?$", Pattern.CASE_INSENSITIVE),
                AccessRule.RuleAction.DENY,
                "",
                new byte[0],
                0L
        );
        List<AccessRule> rules = List.of(denyRule);
        Map<String, List<Integer>> index = Map.of(
                "blocked.internal", new ArrayList<>(List.of(0))
        );
        return new RuleEngine(rules, index);
    }

    @BeforeEach
    void startServer() throws Exception {
        engine = buildEngine();
        HttpProxyHandler handler = new HttpProxyHandler(engine);

        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", handler);
        server.start();

        port = server.getAddress().getPort();
        client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private String baseUrl() {
        return "http://localhost:" + port;
    }

    // -----------------------------------------------------------------------
    // /healthz
    // -----------------------------------------------------------------------

    @Test
    void healthz_returns200() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/healthz"))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
    }

    @Test
    void healthz_bodyContainsOk() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/healthz"))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.body().startsWith("ok"), "expected body starting with 'ok', got: " + resp.body());
    }

    @Test
    void healthz_bodyContainsRuleCount() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/healthz"))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.body().contains("rules=1"), "expected 'rules=1' in body, got: " + resp.body());
    }

    // -----------------------------------------------------------------------
    // /readyz (same handler path)
    // -----------------------------------------------------------------------

    @Test
    void readyz_returns200() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/readyz"))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
    }

    // -----------------------------------------------------------------------
    // Missing / invalid target
    // -----------------------------------------------------------------------

    @Test
    void missingTarget_returns400() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/proxy"))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(400, resp.statusCode());
    }

    @Test
    void missingTarget_bodyContainsUsageHint() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/proxy"))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.body().contains("usage:"), "expected usage hint in body, got: " + resp.body());
    }

    // -----------------------------------------------------------------------
    // DENY rule
    // -----------------------------------------------------------------------

    @Test
    void deniedTarget_returns403() throws Exception {
        String encodedUrl = java.net.URLEncoder.encode("http://blocked.internal/secret",
                java.nio.charset.StandardCharsets.UTF_8);
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/proxy?url=" + encodedUrl))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, resp.statusCode());
    }

    @Test
    void deniedTarget_bodyMentionsRule() throws Exception {
        String encodedUrl = java.net.URLEncoder.encode("http://blocked.internal/secret",
                java.nio.charset.StandardCharsets.UTF_8);
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/proxy?url=" + encodedUrl))
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.body().startsWith("denied by rule"), "expected 'denied by rule' in body, got: " + resp.body());
    }
}

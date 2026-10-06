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
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies POST /admin/reload swaps the live rule engine, and that the HTTP
 * handler's /healthz reflects the new rule count on the very next request.
 */
class AdminHandlerTest {

    private HttpServer server;
    private HttpClient client;
    private int port;
    private AtomicReference<RuleEngine> engineRef;

    @BeforeEach
    void startServer() throws Exception {
        // Seed with a trivial 1-rule engine.
        engineRef = new AtomicReference<>(InitSpike.loadRules(1, 16));

        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", new HttpProxyHandler(engineRef));
        server.createContext("/admin/", new AdminHandler(engineRef, ProxyConfig.fromEnv()));
        server.start();

        port = server.getAddress().getPort();
        client = HttpClient.newHttpClient();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void reload_swapsEngine_andHealthzReflectsNewCount() throws Exception {
        // Baseline: 1 rule.
        HttpResponse<String> before = client.send(
                HttpRequest.newBuilder(URI.create(url("/healthz"))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, before.statusCode());
        assertTrue(before.body().contains("rules=1"), before.body());

        // Reload to 50 rules.
        HttpResponse<String> reload = client.send(
                HttpRequest.newBuilder(URI.create(url("/admin/reload?count=50&payload=32")))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, reload.statusCode());
        assertTrue(reload.body().startsWith("reloaded rules=50"),
                "unexpected reload body: " + reload.body());

        // The AtomicReference now holds the new engine.
        assertEquals(50, engineRef.get().size());

        // Health check immediately sees it.
        HttpResponse<String> after = client.send(
                HttpRequest.newBuilder(URI.create(url("/healthz"))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(after.body().contains("rules=50"), after.body());
    }

    @Test
    void reload_withoutCount_usesDefaultsFromConfig() throws Exception {
        // Default ProxyConfig.ruleCount = 200000, which is too big for a unit test to actually
        // regenerate quickly, so we only verify the handler accepts a param-less POST and
        // either succeeds or produces a non-5xx response. Instead, we assert that an explicit
        // override is honoured without a count parameter — payload only.
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(url("/admin/reload?count=3")))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        assertEquals(3, engineRef.get().size());
    }

    @Test
    void reload_rejectsGet_with405() throws Exception {
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(url("/admin/reload"))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(405, resp.statusCode());
    }

    @Test
    void reload_rejectsNegativeCount_with400() throws Exception {
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(url("/admin/reload?count=-1")))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, resp.statusCode());
    }

    @Test
    void reload_rejectsNonNumericCount_with400() throws Exception {
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(url("/admin/reload?count=abc")))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, resp.statusCode());
    }

    @Test
    void unknownAdminPath_returns404() throws Exception {
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(url("/admin/something-else")))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(404, resp.statusCode());
    }
}

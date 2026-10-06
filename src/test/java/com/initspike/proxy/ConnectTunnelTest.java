package com.initspike.proxy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies HTTPS CONNECT tunnel end-to-end against a plaintext echo upstream
 * (TLS not needed — the tunnel just moves bytes).
 */
class ConnectTunnelTest {

    private ConnectTunnel tunnel;
    private ServerSocket upstream;
    private ExecutorService upstreamPool;

    private static RuleEngine engineWithDeny(String blockedHost) {
        AccessRule deny = new AccessRule(
                42,
                blockedHost,
                "/",
                Pattern.compile("^https?://" + Pattern.quote(blockedHost) + "(/.*)?$",
                        Pattern.CASE_INSENSITIVE),
                AccessRule.RuleAction.DENY,
                "",
                new byte[0],
                0L);
        return new RuleEngine(
                List.of(deny),
                Map.of(blockedHost, new ArrayList<>(List.of(0))));
    }

    @BeforeEach
    void setUp() throws IOException {
        upstreamPool = Executors.newCachedThreadPool();
        upstream = new ServerSocket();
        upstream.bind(new InetSocketAddress("127.0.0.1", 0));
        upstreamPool.submit(this::runEcho);

        tunnel = new ConnectTunnel(0, engineWithDeny("blocked.local"), 4);
        tunnel.start();
    }

    @AfterEach
    void tearDown() throws IOException {
        tunnel.stop();
        upstream.close();
        upstreamPool.shutdownNow();
    }

    private void runEcho() {
        while (!upstream.isClosed()) {
            try {
                Socket client = upstream.accept();
                upstreamPool.submit(() -> {
                    try (client) {
                        InputStream in = client.getInputStream();
                        OutputStream out = client.getOutputStream();
                        byte[] buf = new byte[1024];
                        int n;
                        while ((n = in.read(buf)) > 0) {
                            out.write(buf, 0, n);
                            out.flush();
                        }
                    } catch (IOException ignored) {
                    }
                });
            } catch (IOException ignored) {
                return;
            }
        }
    }

    @Test
    void connect_allowed_establishesTunnelAndEchoesBytes() throws Exception {
        try (Socket client = new Socket("127.0.0.1", tunnel.boundPort())) {
            client.setSoTimeout(5_000);
            String req = "CONNECT 127.0.0.1:" + upstream.getLocalPort() + " HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:" + upstream.getLocalPort() + "\r\n\r\n";
            client.getOutputStream().write(req.getBytes(StandardCharsets.ISO_8859_1));
            client.getOutputStream().flush();

            String status = readLine(client.getInputStream());
            assertNotNull(status);
            assertTrue(status.startsWith("HTTP/1.1 200"), "expected 200 status, got: " + status);
            drainHeaders(client.getInputStream());

            byte[] payload = "hello-tunnel".getBytes(StandardCharsets.UTF_8);
            client.getOutputStream().write(payload);
            client.getOutputStream().flush();

            byte[] echoed = readExactly(client.getInputStream(), payload.length);
            assertArrayEquals(payload, echoed);
        }
    }

    @Test
    void connect_denied_returns403WithRuleId() throws Exception {
        try (Socket client = new Socket("127.0.0.1", tunnel.boundPort())) {
            client.setSoTimeout(5_000);
            String req = "CONNECT blocked.local:443 HTTP/1.1\r\n"
                    + "Host: blocked.local:443\r\n\r\n";
            client.getOutputStream().write(req.getBytes(StandardCharsets.ISO_8859_1));
            client.getOutputStream().flush();

            String status = readLine(client.getInputStream());
            assertNotNull(status);
            assertTrue(status.startsWith("HTTP/1.1 403"), "expected 403, got: " + status);

            String body = readAll(client.getInputStream());
            assertTrue(body.contains("denied by rule 42"),
                    "expected rule id in body, got: " + body);
        }
    }

    @Test
    void nonConnectMethod_returns405() throws Exception {
        try (Socket client = new Socket("127.0.0.1", tunnel.boundPort())) {
            client.setSoTimeout(5_000);
            String req = "GET / HTTP/1.1\r\nHost: whatever\r\n\r\n";
            client.getOutputStream().write(req.getBytes(StandardCharsets.ISO_8859_1));
            client.getOutputStream().flush();

            String status = readLine(client.getInputStream());
            assertNotNull(status);
            assertTrue(status.startsWith("HTTP/1.1 405"), "expected 405, got: " + status);
        }
    }

    @Test
    void stop_releasesPort() throws Exception {
        int port = tunnel.boundPort();
        tunnel.stop();
        // Allow accept loop to exit.
        for (int i = 0; i < 20; i++) {
            try (ServerSocket probe = new ServerSocket()) {
                probe.setReuseAddress(true);
                probe.bind(new InetSocketAddress("127.0.0.1", port));
                return;
            } catch (IOException retry) {
                TimeUnit.MILLISECONDS.sleep(50);
            }
        }
        fail("port " + port + " not released after stop()");
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') break;
            if (b != '\r') buf.write(b);
        }
        return buf.size() == 0 && b == -1 ? null : buf.toString(StandardCharsets.ISO_8859_1);
    }

    private static void drainHeaders(InputStream in) throws IOException {
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            // discard
        }
    }

    private static byte[] readExactly(InputStream in, int n) throws IOException {
        byte[] out = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(out, off, n - off);
            if (r < 0) throw new IOException("eof after " + off + " bytes");
            off += r;
        }
        return out;
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[512];
        int n;
        while ((n = in.read(tmp)) > 0) buf.write(tmp, 0, n);
        return buf.toString(StandardCharsets.UTF_8);
    }
}

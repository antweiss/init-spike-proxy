package com.initspike.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Minimal HTTPS forward proxy: accepts the HTTP CONNECT method on its own
 * socket, consults the rule engine on the target host, and bi-directionally
 * tunnels bytes between the client and the upstream TCP endpoint.
 */
final class ConnectTunnel {
  private final int configuredPort;
  private final RuleEngine engine;
  private final ExecutorService workers;
  private final Thread acceptor;
  private volatile ServerSocket server;

  ConnectTunnel(int port, RuleEngine engine, int workerThreads) {
    this.configuredPort = port;
    this.engine = engine;
    this.workers =
        Executors.newFixedThreadPool(
            workerThreads,
            r -> {
              Thread t = new Thread(r, "connect-worker");
              t.setDaemon(true);
              return t;
            });
    this.acceptor = new Thread(this::acceptLoop, "connect-acceptor");
    this.acceptor.setDaemon(true);
  }

  void start() throws IOException {
    ServerSocket s = new ServerSocket();
    s.setReuseAddress(true);
    s.bind(new InetSocketAddress(configuredPort));
    this.server = s;
    acceptor.start();
  }

  int boundPort() {
    ServerSocket s = server;
    return s == null ? configuredPort : s.getLocalPort();
  }

  void stop() {
    ServerSocket s = server;
    if (s != null) {
      try {
        s.close();
      } catch (IOException ignored) {
      }
    }
    workers.shutdownNow();
    acceptor.interrupt();
  }

  private void acceptLoop() {
    ServerSocket s = server;
    while (s != null && !s.isClosed()) {
      try {
        Socket client = s.accept();
        workers.submit(() -> handle(client));
      } catch (IOException e) {
        if (s.isClosed()) {
          return;
        }
      }
    }
  }

  private void handle(Socket client) {
    try {
      client.setSoTimeout(30_000);
      InputStream in = client.getInputStream();

      String requestLine = readLine(in);
      if (requestLine == null || requestLine.isEmpty()) {
        close(client);
        return;
      }

      String[] parts = requestLine.split(" ");
      if (parts.length < 2 || !"CONNECT".equalsIgnoreCase(parts[0])) {
        writeStatus(client, 405, "Method Not Allowed", "only CONNECT is supported on this port");
        close(client);
        return;
      }

      // Drain remaining request headers.
      String header;
      while ((header = readLine(in)) != null && !header.isEmpty()) {
        // discard
      }

      HostPort target = parseHostPort(parts[1]);
      if (target == null) {
        writeStatus(client, 400, "Bad Request", "invalid CONNECT target: " + parts[1]);
        close(client);
        return;
      }

      AccessRule rule = engine.match(URI.create("https://" + target.host + "/"));
      if (rule.action == AccessRule.RuleAction.DENY) {
        writeStatus(client, 403, "Forbidden", "denied by rule " + rule.id);
        close(client);
        return;
      }

      Socket upstream = new Socket();
      try {
        upstream.connect(new InetSocketAddress(target.host, target.port), 10_000);
      } catch (IOException e) {
        writeStatus(client, 502, "Bad Gateway", "upstream connect failed: " + e.getMessage());
        close(client);
        close(upstream);
        return;
      }

      client.setSoTimeout(0);
      upstream.setSoTimeout(0);

      OutputStream clientOut = client.getOutputStream();
      clientOut.write(
          ("HTTP/1.1 200 Connection Established\r\n"
                  + "X-Proxy-Rule-Id: "
                  + rule.id
                  + "\r\n\r\n")
              .getBytes(StandardCharsets.ISO_8859_1));
      clientOut.flush();

      tunnel(client, upstream);
    } catch (IOException e) {
      close(client);
    }
  }

  private void tunnel(Socket client, Socket upstream) {
    Thread upstreamToClient =
        new Thread(() -> copyAndHalfClose(upstream, client), "tunnel-up->client");
    upstreamToClient.setDaemon(true);
    upstreamToClient.start();
    copyAndHalfClose(client, upstream);
    try {
      upstreamToClient.join(2_000);
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
    }
    close(client);
    close(upstream);
  }

  private static void copyAndHalfClose(Socket src, Socket dst) {
    byte[] buf = new byte[8192];
    try {
      InputStream in = src.getInputStream();
      OutputStream out = dst.getOutputStream();
      int n;
      while ((n = in.read(buf)) > 0) {
        out.write(buf, 0, n);
        out.flush();
      }
    } catch (IOException ignored) {
    } finally {
      try {
        if (!dst.isClosed() && !dst.isOutputShutdown()) {
          dst.shutdownOutput();
        }
      } catch (IOException ignored) {
      }
    }
  }

  /** Reads bytes up to and including LF, returning the line without the trailing CRLF. */
  private static String readLine(InputStream in) throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
    int b;
    boolean any = false;
    while ((b = in.read()) != -1) {
      any = true;
      if (b == '\n') {
        break;
      }
      if (b != '\r') {
        buf.write(b);
      }
      if (buf.size() > 8192) {
        throw new IOException("header line too long");
      }
    }
    if (!any) {
      return null;
    }
    return buf.toString(StandardCharsets.ISO_8859_1);
  }

  private static HostPort parseHostPort(String raw) {
    int colon = raw.lastIndexOf(':');
    if (colon <= 0 || colon == raw.length() - 1) {
      return null;
    }
    String host = raw.substring(0, colon);
    int port;
    try {
      port = Integer.parseInt(raw.substring(colon + 1));
    } catch (NumberFormatException e) {
      return null;
    }
    if (port < 1 || port > 65535) {
      return null;
    }
    return new HostPort(host, port);
  }

  private static void writeStatus(Socket client, int code, String reason, String body) {
    try {
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      String head =
          "HTTP/1.1 "
              + code
              + " "
              + reason
              + "\r\nContent-Length: "
              + bytes.length
              + "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n";
      OutputStream out = client.getOutputStream();
      out.write(head.getBytes(StandardCharsets.ISO_8859_1));
      out.write(bytes);
      out.flush();
    } catch (IOException ignored) {
    }
  }

  private static void close(Socket s) {
    if (s == null) {
      return;
    }
    try {
      s.close();
    } catch (IOException ignored) {
    }
  }

  private record HostPort(String host, int port) {}
}

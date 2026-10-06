package com.initspike.proxy;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

public final class ProxyApp {
  public static void main(String[] args) throws Exception {
    ProxyConfig config = ProxyConfig.fromEnv();
    AtomicReference<RuleEngine> engineRef = new AtomicReference<>(InitSpike.run(config));

    HttpServer server = HttpServer.create(new InetSocketAddress(config.listenPort), 0);
    server.createContext("/", new HttpProxyHandler(engineRef));
    server.createContext("/admin/", new AdminHandler(engineRef, config));
    server.setExecutor(Executors.newFixedThreadPool(config.workerThreads));
    server.start();

    ConnectTunnel tunnel = new ConnectTunnel(config.connectPort, engineRef, config.workerThreads);
    tunnel.start();

    System.out.printf(
        "proxy listening on :%d  GET /healthz  GET /proxy?url=https://example.com  POST /admin/reload%n",
        config.listenPort);
    System.out.printf("CONNECT tunnel listening on :%d (HTTPS forward proxy)%n", tunnel.boundPort());
  }
}

package com.initspike.proxy;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

public final class ProxyApp {
  public static void main(String[] args) throws Exception {
    ProxyConfig config = ProxyConfig.fromEnv();
    RuleEngine engine = InitSpike.run(config);

    HttpServer server = HttpServer.create(new InetSocketAddress(config.listenPort), 0);
    HttpProxyHandler handler = new HttpProxyHandler(engine);
    server.createContext("/", handler);
    server.setExecutor(Executors.newFixedThreadPool(config.workerThreads));
    server.start();

    ConnectTunnel tunnel = new ConnectTunnel(config.connectPort, engine, config.workerThreads);
    tunnel.start();

    System.out.printf(
        "proxy listening on :%d  GET /healthz  GET /proxy?url=https://example.com%n",
        config.listenPort);
    System.out.printf("CONNECT tunnel listening on :%d (HTTPS forward proxy)%n", tunnel.boundPort());
  }
}

package com.initspike.proxy;

final class ProxyConfig {
  final int listenPort;
  final int ruleCount;
  final int cpuPasses;
  final int payloadBytes;
  final int workerThreads;

  private ProxyConfig(int listenPort, int ruleCount, int cpuPasses, int payloadBytes, int workerThreads) {
    this.listenPort = listenPort;
    this.ruleCount = ruleCount;
    this.cpuPasses = cpuPasses;
    this.payloadBytes = payloadBytes;
    this.workerThreads = workerThreads;
  }

  static ProxyConfig fromEnv() {
    int cores = Math.max(1, Runtime.getRuntime().availableProcessors());
    return new ProxyConfig(
        envInt("LISTEN_PORT", 8080),
        envInt("RULE_COUNT", 200_000),
        envInt("INIT_CPU_PASSES", 4),
        envInt("RULE_PAYLOAD_BYTES", 256),
        envInt("WORKER_THREADS", cores * 2));
  }

  private static int envInt(String name, int fallback) {
    String raw = System.getenv(name);
    if (raw == null || raw.isBlank()) {
      return fallback;
    }
    return Integer.parseInt(raw.trim());
  }
}

package com.initspike.proxy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.SplittableRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

/**
 * Startup work that is intentionally expensive: compile a large rule set,
 * keep it in memory, and run CPU-heavy hashing / regex / sieve passes.
 */
final class InitSpike {

  static RuleEngine run(ProxyConfig config) {
    long started = System.nanoTime();
    System.out.printf(
        "init: loading %d rules, %d CPU passes, payload=%d bytes%n",
        config.ruleCount, config.cpuPasses, config.payloadBytes);

    burnCpu(config);
    RuleEngine engine = loadRules(config.ruleCount, config.payloadBytes);

    long elapsedMs = (System.nanoTime() - started) / 1_000_000L;
    Runtime rt = Runtime.getRuntime();
    long usedMb = (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
    System.out.printf(
        "init: ready in %d ms | heap used ~%d MiB | rules=%d | indexes=%d%n",
        elapsedMs, usedMb, engine.size(), engine.indexSize());
    return engine;
  }

  private static void burnCpu(ProxyConfig config) {
    int cores = Math.max(1, Runtime.getRuntime().availableProcessors());
    int workUnits = Math.max(cores * 8_000, config.ruleCount / 4);

    for (int pass = 0; pass < config.cpuPasses; pass++) {
      final int currentPass = pass;
      long checksum =
          IntStream.range(0, workUnits)
              .parallel()
              .mapToLong(i -> heavyDigest(i, currentPass) ^ sieveFragment(i + currentPass))
              .sum();
      System.out.printf("init: CPU pass %d/%d checksum=%d%n", pass + 1, config.cpuPasses, checksum);
    }
  }

  private static long heavyDigest(int seed, int pass) {
    try {
      MessageDigest sha = MessageDigest.getInstance("SHA-256");
      byte[] buf = new byte[4096];
      new SplittableRandom(((long) seed << 32) ^ pass).nextBytes(buf);
      byte[] out = sha.digest(buf);
      long v = 0;
      for (int i = 0; i < 8; i++) {
        v = (v << 8) | (out[i] & 0xff);
      }
      return v;
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Small sieve fragment so each parallel task does real integer work, not just hashing. */
  private static long sieveFragment(int seed) {
    int n = 4_096 + (Math.abs(seed) % 1_024);
    boolean[] composite = new boolean[n];
    long sum = 0;
    for (int i = 2; i < n; i++) {
      if (!composite[i]) {
        sum += i;
        for (int j = i * i; j < n && j > 0; j += i) {
          composite[j] = true;
        }
      }
    }
    return sum;
  }

  static RuleEngine loadRules(int ruleCount, int payloadBytes) {
    List<AccessRule> rules =
        IntStream.range(0, ruleCount)
            .parallel()
            .mapToObj(i -> compileRule(i, payloadBytes))
            .toList();

    ConcurrentHashMap<String, List<Integer>> hostIndex = new ConcurrentHashMap<>();
    for (AccessRule rule : rules) {
      hostIndex.computeIfAbsent(rule.hostGlob, k -> new ArrayList<>()).add(rule.id);
    }

    return new RuleEngine(List.copyOf(rules), hostIndex);
  }

  private static AccessRule compileRule(int id, int payloadBytes) {
    String host = "svc-" + (id % 4_096) + ".internal.example";
    String path = "/api/v" + (id % 9) + "/resource/" + id;
    String regex = "^https?://" + Pattern.quote(host) + path + "(/.*)?$";
    Pattern compiled = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);

    AccessRule.RuleAction action =
        switch (id % 17) {
          case 0 -> AccessRule.RuleAction.DENY;
          case 1, 2 -> AccessRule.RuleAction.REWRITE;
          default -> AccessRule.RuleAction.ALLOW;
        };

    String rewrite = action == AccessRule.RuleAction.REWRITE ? "https://origin.example" + path : "";
    byte[] payload = paddedPayload(id, payloadBytes);
    long fingerprint = fnv1a64(payload) ^ compiled.pattern().hashCode();

    return new AccessRule(id, host, path, compiled, action, rewrite, payload, fingerprint);
  }

  private static byte[] paddedPayload(int id, int payloadBytes) {
    String seed = "rule-" + id + "-policy-annotation-";
    byte[] prefix = seed.getBytes(StandardCharsets.UTF_8);
    byte[] out = new byte[Math.max(payloadBytes, prefix.length)];
    System.arraycopy(prefix, 0, out, 0, prefix.length);
    for (int i = prefix.length; i < out.length; i++) {
      out[i] = (byte) ((id * 31 + i) & 0xff);
    }
    return out;
  }

  private static long fnv1a64(byte[] data) {
    long hash = 0xcbf29ce484222325L;
    for (byte b : data) {
      hash ^= (b & 0xff);
      hash *= 0x100000001b3L;
    }
    return hash;
  }
}

# Init-spike HTTP proxy

A JDK 17 forwarding proxy that **burns CPU and retains a large ACL/WAF-style rule set on startup**, then serves traffic. Useful as a workload that shows a startup resource spike (CPU + heap) before settling into a cheaper request path.

## What init does

1. **CPU spike** — several parallel passes of SHA-256 over 4 KiB buffers plus a small prime sieve on every worker.
2. **Memory spike** — compiles `RULE_COUNT` regex rules (default 200 000), each with a compiled `Pattern`, host/path metadata, and a retained payload byte array, then builds a host → rule-id index.

After init, matching is an index lookup plus a short scan; the heavy compile work is not repeated per request.

## Run

```bash
gradle build
java -jar build/libs/init-spike-proxy-1.0.0.jar
```

Health check:

```bash
curl -s localhost:8080/healthz
```

Forward a URL (explicit query form, no CONNECT tunneling):

```bash
curl -s 'localhost:8080/proxy?url=https://example.com'
```

## Environment

| Variable | Default | Role |
|---|---|---|
| `LISTEN_PORT` | `8080` | Bind port |
| `RULE_COUNT` | `200000` | Rules compiled and retained on heap |
| `INIT_CPU_PASSES` | `4` | Extra full-core hash/sieve passes before rule load |
| `RULE_PAYLOAD_BYTES` | `256` | Extra bytes kept per rule |
| `WORKER_THREADS` | `2 × cores` | `HttpServer` executor size |

Tune the spike up with more rules/passes, or down for laptops:

```bash
RULE_COUNT=50000 INIT_CPU_PASSES=2 java -jar build/libs/init-spike-proxy-1.0.0.jar
```

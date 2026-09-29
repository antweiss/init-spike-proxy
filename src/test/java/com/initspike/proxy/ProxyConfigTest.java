package com.initspike.proxy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ProxyConfig. Because fromEnv() reads System.getenv() we exercise
 * only the defaults path here (env vars are not set in the test JVM).
 * The private constructor and envInt helper are covered transitively.
 */
class ProxyConfigTest {

    @Test
    void fromEnv_listenPort_defaultIs8080() {
        ProxyConfig config = ProxyConfig.fromEnv();
        assertEquals(8080, config.listenPort);
    }

    @Test
    void fromEnv_ruleCount_defaultIs200000() {
        ProxyConfig config = ProxyConfig.fromEnv();
        assertEquals(200_000, config.ruleCount);
    }

    @Test
    void fromEnv_cpuPasses_defaultIs4() {
        ProxyConfig config = ProxyConfig.fromEnv();
        assertEquals(4, config.cpuPasses);
    }

    @Test
    void fromEnv_payloadBytes_defaultIs256() {
        ProxyConfig config = ProxyConfig.fromEnv();
        assertEquals(256, config.payloadBytes);
    }

    @Test
    void fromEnv_workerThreads_atLeast2() {
        // At least 1 core × 2; we can't know the exact machine count but it must be positive.
        ProxyConfig config = ProxyConfig.fromEnv();
        assertTrue(config.workerThreads >= 2, "workerThreads should be >= 2, got " + config.workerThreads);
    }

    @Test
    void fromEnv_workerThreads_isEvenMultipleOfCores() {
        // workerThreads = cores * 2, so it must be even.
        ProxyConfig config = ProxyConfig.fromEnv();
        assertEquals(0, config.workerThreads % 2, "workerThreads should be a multiple of 2");
    }
}
